#!/bin/bash
# Brings the Samba AD DC up deterministically and idempotently:
#   1. provisions realm MERIDIAN.LAB once (skipped on restart),
#   2. creates the low-privilege user `t.okonkwo` and the kerberoastable `svc-mssql-tms`,
#   3. plants the flag in a share only svc-mssql-tms may read,
#   4. runs the single `samba` AD DC process in the foreground.
# Re-running it against an already-provisioned DC changes nothing (safe restart).
#
# Scenario: Meridian Freight, a logistics company. The Transport Management System's database
# runs under a dedicated service account (svc-mssql-tms) whose SPN makes it kerberoastable, and
# whose password is a weak company-and-year word.
set -euo pipefail

REALM="MERIDIAN.LAB"
DOMAIN="MERIDIAN"
# DC administrator password: infrastructure only, never shown to the student.
ADMIN_PASS="DCAdm1n#Meridian2024"
# Student's low-privilege foothold account (a freight dispatcher; handed out in the lab message).
FOOTHOLD_USER="t.okonkwo"
FOOTHOLD_PASS="Dispatch!2024"
# Kerberoastable service account for the Transport Management System database: policy-compliant
# but a weak, wordlist-crackable word.
SVC_USER="svc-mssql-tms"
SVC_PASS="Freight2022"
SVC_SPN="MSSQLSvc/dc.meridian.lab:1433"

PRIVATE_DIR="/var/lib/samba/private"
STAMP="${PRIVATE_DIR}/.isoloom-provisioned"

log() { echo "[dc] $*" >&2; }

if [ ! -f "${STAMP}" ]; then
  log "provisioning ${REALM} ..."
  rm -f /etc/samba/smb.conf
  # posix:eadb keeps NT ACLs in a tdb instead of security.* xattrs, so provisioning and the
  # file server work in an unprivileged container (no CAP_SYS_ADMIN). "ldap server require
  # strong auth = no" lets the student enumerate the SPN over plain LDAP from the attack box.
  # Both --options persist into the generated smb.conf, so the running daemon uses them too.
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="${REALM}" \
    --domain="${DOMAIN}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name=dc \
    --adminpass="${ADMIN_PASS}" \
    --option="posix:eadb=/var/lib/samba/eadb.tdb" \
    --option="ldap server require strong auth = no" >/dev/null

  # Kerberos client config and resolver point the DC at its own internal DNS.
  cp -f "${PRIVATE_DIR}/krb5.conf" /etc/krb5.conf

  # Publish the share that guards the flag.
  cat /opt/kerberoast/vault-share.conf >> /etc/samba/smb.conf

  touch "${STAMP}"
  log "provisioning done."
else
  log "already provisioned; reusing ${PRIVATE_DIR}."
fi

# Resolver: the DC resolves its own realm through Samba's internal DNS.
printf 'nameserver 127.0.0.1\nsearch meridian.lab\n' > /etc/resolv.conf 2>/dev/null || true
grep -q 'dc.meridian.lab' /etc/hosts 2>/dev/null || \
  printf '127.0.0.1 dc.meridian.lab dc\n' >> /etc/hosts 2>/dev/null || true

# Users and the kerberoastable SPN are created offline against the local sam.ldb, so this
# works whether or not the samba process is already running.
if ! samba-tool user list 2>/dev/null | grep -qx "${FOOTHOLD_USER}"; then
  log "creating user ${FOOTHOLD_USER}"
  samba-tool user create "${FOOTHOLD_USER}" "${FOOTHOLD_PASS}" \
    --description="Dispatch desk" >/dev/null
fi

if ! samba-tool user list 2>/dev/null | grep -qx "${SVC_USER}"; then
  log "creating service account ${SVC_USER}"
  samba-tool user create "${SVC_USER}" "${SVC_PASS}" \
    --description="MSSQL service account (Transport Management System)" >/dev/null
fi

# Register the SPN that makes svc-mssql-tms kerberoastable (idempotent).
if ! samba-tool spn list "${SVC_USER}" 2>/dev/null | grep -qi "${SVC_SPN}"; then
  log "registering SPN ${SVC_SPN} on ${SVC_USER}"
  samba-tool spn add "${SVC_SPN}" "${SVC_USER}" >/dev/null
fi

# Force RC4 (etype 23) as the account's supported encryption type, so the roasted TGS is the
# classic, fast-to-crack $krb5tgs$23$ hash rather than AES.
SVC_DN="$(samba-tool user show "${SVC_USER}" 2>/dev/null | awk -F': ' '/^dn:/{print $2; exit}')"
if [ -n "${SVC_DN}" ]; then
  cat > /tmp/enctypes.ldif <<EOF
dn: ${SVC_DN}
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 4
EOF
  ldbmodify -H "${PRIVATE_DIR}/sam.ldb" /tmp/enctypes.ldif >/dev/null 2>&1 || true
  rm -f /tmp/enctypes.ldif
fi

# Passwords never expire, so the lab behaves the same on day 1 and day 60.
samba-tool user setexpiry "${FOOTHOLD_USER}" --noexpiry >/dev/null 2>&1 || true
samba-tool user setexpiry "${SVC_USER}" --noexpiry >/dev/null 2>&1 || true

# Plant the flag inside the manifests share. CTF_FLAG_MAIN is delivered by the launcher at
# /ctf/flag (Isoloom's sensitive-input-as-file mechanism); fall back to a dev flag for a bare run.
mkdir -p /srv/manifests
if [ -s /ctf/flag ]; then
  cp -f /ctf/flag /srv/manifests/flag.txt
else
  printf 'FLAG{dev-kerberoast-meridian}\n' > /srv/manifests/flag.txt
fi
chmod 0444 /srv/manifests/flag.txt

log "starting samba (AD DC) ..."
exec samba --interactive --no-process-group
