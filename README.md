# ad-reanimate

**List and restore Active Directory objects that were deleted into the AD Recycle Bin — over LDAP, from Linux.**

Windows has `Restore-ADObject`. Linux has almost nothing: impacket has no Recycle Bin support, netexec's
`recyclebin` module is about SMB file shares (not directory objects), and the only CLI that does it today is
`bloodyAD set restore`. The operation itself is trivial — **one LDAP Modify** — it is the plumbing around it
that keeps people on PowerShell:

* the `SHOW_DELETED` control (`1.2.840.113556.1.4.417`) has to be sent with **both** the search and the modify;
* a tombstone lives at `<name>\x0aDEL:<objectGUID>,CN=Deleted Objects,<domain NC>` — the separator is a `0x0A`
  byte (rendered `\0ADEL` in escaped form), which is why hand-built DNs fail;
* **several tombstones can share one CN.** Restoring "by name" brings back an arbitrary one, and the wrong
  identity usually has none of the rights you were after. This is the mistake that costs days.

This tool wraps those three facts and refuses to guess.

## Install

### pipx (recommended — isolated venv, `reanimate` on your PATH)

```bash
pipx install git+https://github.com/Dar1anMar1us/ad-reanimate
reanimate --help

# or run it without installing anything:
pipx run --spec git+https://github.com/Dar1anMar1us/ad-reanimate reanimate --help
```

### From a clone

```bash
git clone https://github.com/Dar1anMar1us/ad-reanimate.git && cd ad-reanimate
pip install -r requirements.txt        # or: pip install .
./reanimate.py --help
```

Requires Python 3.8+ and **`ldap3` only**. The DN/SID/GUID logic is stdlib-only and unit-tested offline
(`python3 tests/test_offline.py` — no directory needed). Every example below uses `./reanimate.py`; if you
installed it with pipx, drop the `./` and call `reanimate`.

## How a restore actually works (and why `isDeleted=FALSE` fails)

AD does not restore an object by flipping a flag. It is a single LDAP Modify against the **tombstone DN**,
with the `SHOW_DELETED` control (critical), that:

* **REPLACES `distinguishedName`** with the real DN — rebuilt from `msDS-LastKnownRDN` + `lastKnownParent`;
  this is what moves the object out of `CN=Deleted Objects`, and
* **DELETES `isDeleted`**.

Send only `replace: isDeleted / isDeleted: FALSE` and the DC answers **`unwillingToPerform`** — the request
looks right and is silently malformed. Verified both ways against a Windows Server 2019 DC.

Because the restore DN is rebuilt from `lastKnownParent`, a tombstone whose parent is gone cannot be restored
safely: the tool refuses and asks for `--new-parent`. `--new-name` renames while restoring (RDN + name/SPN/UPN).

## Usage

```bash
# 1. what is in the bin?
./reanimate.py list -H dc01.corp.local -u jdoe -p 'P@ssw0rd!' --base 'DC=corp,DC=local'

#    ...machine-readable, when you want to grep/match it
./reanimate.py list -H dc01 -u jdoe -p 'P@ssw0rd!' --base 'DC=corp,DC=local' --json

# 2. find the identity that actually matters. Tooling often cannot resolve it, e.g.
#    certipy: "Failed to lookup object with SID 'S-1-5-21-...-1111'"
./reanimate.py list   -H dc01 -u jdoe -p 'P@ssw0rd!' --base 'DC=corp,DC=local' --sid 'S-1-5-21-...-1111'
./reanimate.py list   -H dc01 -u jdoe -p 'P@ssw0rd!' --base 'DC=corp,DC=local' --name cert_admin   # may be ambiguous

# 3. restore — dry-run unless --apply, and it verifies afterwards
./reanimate.py restore -H dc01 -u jdoe -p 'P@ssw0rd!' --base 'DC=corp,DC=local' --rid 1111 --apply
```

Selectors: `--guid`, `--sid`, `--rid`, `--name`, `--last-known-parent` (combinable). With more than one match
the tool prints the candidates and exits `2` instead of guessing.

Auth/transport: simple bind by default — a **bare sAMAccountName is rejected by AD**, so the tool qualifies it
with `@<domain from --base>` (or use `--domain`); `--ldaps`, `--starttls`, `--port`, `--insecure`, `--timeout`
are available. An LDAPS bind is worth preferring — some hardened domains block plain LDAP writes.

## What authorises a restore

The **Reanimate-Tombstones** extended right (`45ec5156-db7e-47bb-b53f-dbeb2d03c40f`) on the domain NC or on the
deleted object's last-known parent — or any higher right that covers it (`AllExtendedRights`, `GenericAll`).
Check before you bother:

```bash
impacket-dacledit -action read -dc-ip <DC> -target-dn 'DC=corp,DC=local' -principal jdoe 'corp.local/jdoe:P@ss'
```

You also need to be able to *see* deleted objects, which is what the `SHOW_DELETED` control buys you
(without it, `CN=Deleted Objects` looks empty — that is why "there is nothing in the Recycle Bin" is usually
a tooling problem, not a fact).

## Cleanup

Restoring an object is a change to the directory: if you brought something back only to use it, either return it
to the tombstone state (`Remove-ADUser` / `Remove-ADObject` on Windows, or delete the object again) or say so
explicitly in your report. The restore itself, and the delete, both leave directory events.

## Notes / limitations

* Password bind only in this version; pass-the-hash (`ldap3` + NTLM) is the obvious next addition.
* Not a Recycle Bin *dump* tool: it reads the tombstones that your rights let you see.
* `whenChanged`/`uac`/`description` are listed when present, useful when two tombstones share a CN.

## Verified against

* A Windows Server 2019 domain controller (Recycle Bin in use): three same-named tombstones, SID/RID-based
  disambiguation, the ambiguity refusal, a real restore (`modify result: True`), independent confirmation of
  the restored DN with `ldapsearch`, and a clean return to the tombstone state afterwards.
* A Windows Server 2008 R2 domain (different forest): objects with **no SID** (GPO tombstones), computer and
  group tombstones, and `lastKnownParent` under nested OUs — all listed and matched correctly.
* The wrong modify shape was reproduced too, so the tool's failure hints match reality (`unwillingToPerform`
  for `isDeleted=FALSE`, `noSuchObject` for a mangled tombstone DN).
* Offline unit tests for SID/GUID/DN/identity handling: `tests/test_offline.py`.

MIT licensed. Techniques only — use it on systems you are authorised to test.
