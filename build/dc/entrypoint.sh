#!/bin/bash
# Brings the Samba AD DC up deterministically and idempotently:
#   1. provisions realm NORTH.SEVENKINGDOMS.LOCAL once (skipped on restart),
#   2. creates the low-privilege user `hodor` and the kerberoastable `svc_sql`,
#   3. plants the flag in a share only svc_sql may read,
#   4. runs the single `samba` AD DC process in the foreground.
# Re-running it against an already-provisioned DC changes nothing (safe restart).
set -euo pipefail

REALM="NORTH.SEVENKINGDOMS.LOCAL"
DOMAIN="NORTH"
# DC administrator password: infrastructure only, never shown to the student.
ADMIN_PASS="DCAdm1n#Winterfell2024"
# Student's low-privilege foothold account (handed out in the lab message).
HODOR_PASS="Hodor123!"
# Kerberoastable service account: policy-compliant but a weak, wordlist-crackable word.
SVC_USER="svc_sql"
SVC_PASS="Winter2022"
SVC_SPN="MSSQLSvc/dc.north.sevenkingdoms.local:1433"

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

  # Publish the vault share that guards the flag.
  cat /opt/kerberoast/vault-share.conf >> /etc/samba/smb.conf

  touch "${STAMP}"
  log "provisioning done."
else
  log "already provisioned; reusing ${PRIVATE_DIR}."
fi

# Resolver: the DC resolves its own realm through Samba's internal DNS.
printf 'nameserver 127.0.0.1\nsearch north.sevenkingdoms.local\n' > /etc/resolv.conf 2>/dev/null || true
grep -q 'dc.north.sevenkingdoms.local' /etc/hosts 2>/dev/null || \
  printf '127.0.0.1 dc.north.sevenkingdoms.local dc\n' >> /etc/hosts 2>/dev/null || true

# Users and the kerberoastable SPN are created offline against the local sam.ldb, so this
# works whether or not the samba process is already running.
if ! samba-tool user list 2>/dev/null | grep -qx "hodor"; then
  log "creating user hodor"
  samba-tool user create hodor "${HODOR_PASS}" >/dev/null
fi

if ! samba-tool user list 2>/dev/null | grep -qx "${SVC_USER}"; then
  log "creating service account ${SVC_USER}"
  samba-tool user create "${SVC_USER}" "${SVC_PASS}" \
    --description="MSSQL service account" >/dev/null
fi

# Register the SPN that makes svc_sql kerberoastable (idempotent).
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
samba-tool user setexpiry hodor --noexpiry >/dev/null 2>&1 || true
samba-tool user setexpiry "${SVC_USER}" --noexpiry >/dev/null 2>&1 || true

# Plant the flag inside the vault. CTF_FLAG_MAIN is delivered by the launcher at /ctf/flag
# (Isoloom's sensitive-input-as-file mechanism); fall back to a dev flag for a bare run.
mkdir -p /srv/vault
if [ -s /ctf/flag ]; then
  cp -f /ctf/flag /srv/vault/flag.txt
else
  printf 'FLAG{dev-kerberoast-north-svc_sql}\n' > /srv/vault/flag.txt
fi
chmod 0444 /srv/vault/flag.txt

log "starting samba (AD DC) ..."
exec samba --interactive --no-process-group
