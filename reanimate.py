#!/usr/bin/env python3
"""
reanimate — list and restore Active Directory objects that were deleted into the AD Recycle Bin,
straight over LDAP from Linux.

Why this exists: `Restore-ADObject` is PowerShell-only, impacket and netexec have nothing for the
Recycle Bin (netexec's `recyclebin` module is SMB file shares, not directory objects), and
`bloodyAD set restore` is the only CLI that does it today. The operation itself is one LDAP Modify
with the SHOW_DELETED control — this tool makes that explicit, scriptable and safe.

The two things that actually bite an operator:
  1. the tombstone DN form — `<name>\x0aDEL:<objectGUID>,CN=Deleted Objects,<NC>` (the separator is a
     0x0A byte, rendered `\\0ADEL` when escaped). It is normally taken verbatim from a search.
  2. several tombstones can share one CN. Restoring "by name" picks an arbitrary one; this tool
     refuses to guess and makes you disambiguate by GUID / SID / RID / lastKnownParent.

Authorisation for the restore: the Reanimate-Tombstones extended right
(45ec5156-db7e-47bb-b53f-dbeb2d03c40f) on the domain NC or on the deleted object's last-known
parent — or any higher right (GenericAll / AllExtendedRights) that covers it.

Examples
--------
    # what is in the bin?
    ./reanimate.py list -H dc01.corp.local -u jdoe -p 'P@ss' --base 'DC=corp,DC=local'

    # which cert_admin is the one that matters? match the SID that tools could not resolve
    ./reanimate.py list -H dc01 -u jdoe -p 'P@ss' --base 'DC=corp,DC=local' --name cert_admin --json

    # restore (dry-run unless --apply), then verify
    ./reanimate.py restore -H dc01 -u jdoe -p 'P@ss' --base 'DC=corp,DC=local' --rid 1111 --apply
"""

import argparse
import json
import sys
import uuid

SHOW_DELETED_OID = "1.2.840.113556.1.4.417"      # LDAP_SERVER_SHOW_DELETED_OID
REANIMATE_TOMBSTONES_GUID = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"
DELETED_FILTER = "(isDeleted=TRUE)"
DELETED_CN = "CN=Deleted Objects"

ATTRS = [
    "distinguishedName", "name", "sAMAccountName", "objectGUID", "objectSid",
    "lastKnownParent", "msDS-LastKnownRDN", "whenCreated", "whenChanged", "isDeleted",
    "userAccountControl", "objectClass", "description",
]

# --------------------------------------------------------------------------- pure helpers
# Kept dependency-free (stdlib only) so they are unit-testable without a directory.


def sid_to_str(raw):
    """Binary objectSid -> 'S-1-5-21-...-RID'."""
    if raw is None:
        return ""
    if isinstance(raw, str):                      # some libs hand back the string form already
        return raw
    b = bytes(raw)
    if len(b) < 8:
        return ""
    revision, sub_count = b[0], b[1]
    authority = int.from_bytes(b[2:8], "big")
    subs = [int.from_bytes(b[8 + 4 * i: 12 + 4 * i], "little") for i in range(sub_count)]
    return "S-{}".format("-".join(str(x) for x in [revision, authority] + subs))


def sid_rid(raw_or_str):
    """Last sub-authority of a SID (the RID), or None."""
    s = raw_or_str if isinstance(raw_or_str, str) else sid_to_str(raw_or_str)
    if not s:
        return None
    try:
        return int(s.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return None


def guid_to_str(raw):
    """Binary objectGUID (16 bytes, little-endian mixed) -> canonical GUID string."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip("{}").lower()
    b = bytes(raw)
    if len(b) == 16:
        return str(uuid.UUID(bytes_le=b)).lower()
    return b.hex()


def tombstone_dn(name, guid):
    """The DN of a tombstone RDN. The separator between the name and 'DEL:' is 0x0A."""
    return "CN={}\nDEL:{},{}".format(name, guid, DELETED_CN)


def norm(value):
    return (value or "").strip().rstrip(",").lower()


def clean_deleted_name(value):
    """AD walks the tombstone suffix into the name itself: 'cert_admin\\nDEL:<guid>'.

    Both `name` and `sAMAccountName` come back like that for a deleted object, which breaks both
    the display and a `--name cert_admin` match. Keep only the pre-DEL part.
    """
    if not value:
        return ""
    s = str(value)
    for marker in ("\nDEL:", "\x00DEL:"):
        if marker in s:
            s = s.split(marker)[0]
            break
    return s.strip()


def is_tombstone(row):
    """True for a real deleted object, False for the 'CN=Deleted Objects' container itself."""
    return "\nDEL:" in (row.get("raw_name") or "") or "\x00DEL:" in (row.get("raw_name") or "")


def restored_dn(row, new_name=None, new_parent=None):
    """Where the object lands when it comes back.

    A restore is not 'isDeleted=FALSE': AD performs it by **replacing the DN** (out of
    CN=Deleted Objects) **and deleting the isDeleted attribute** in the same modify. The target DN is
    built from the last known RDN + lastKnownParent, which is why those attributes are fetched first.
    """
    rdn = new_name or row.get("last_known_rdn") or clean_deleted_name(row.get("raw_name"))
    if not rdn:
        raise ValueError("no last-known RDN and no --new-name: cannot rebuild the DN")
    if "=" not in rdn:                       # msDS-LastKnownRDN may come back as a bare value
        rdn = "CN={}".format(rdn)
    parent = new_parent or row.get("last_known_parent")
    if not parent:
        raise ValueError("lastKnownParent is missing — pass --new-parent (refusing to guess the OU)")
    if "DEL:" in parent:
        raise ValueError("lastKnownParent is itself a deleted object ({}…) — restore the parent first, "
                         "or pass --new-parent".format(parent[:70]))
    return "{},{}".format(rdn, parent)


def match_tombstones(tombstones, *, guid=None, sid=None, rid=None, name=None,
                     last_known_parent=None):
    """Filter a tombstone list. Deliberately does NOT break ties — see select()."""
    out = list(tombstones)
    if guid:
        want = guid.strip("{}").lower()
        out = [t for t in out if t.get("guid", "").lower() == want]
    if sid:
        want = sid.strip().upper()
        out = [t for t in out if t.get("sid", "").upper() == want]
    if rid is not None:
        out = [t for t in out if sid_rid(t.get("sid", "")) == int(rid)]
    if name:
        want = name.strip().lower()
        out = [t for t in out
               if want in (t.get("name", "").lower(), t.get("sam", "").lower())]
    if last_known_parent:
        want = norm(last_known_parent)
        out = [t for t in out if norm(t.get("last_known_parent")) == want]
    return out


def select(tombstones, **kw):
    """Return (chosen, candidates). Raises ValueError when the match is ambiguous or empty."""
    cands = match_tombstones(tombstones, **kw)
    if not cands:
        raise ValueError("no tombstone matches those criteria")
    if len(cands) > 1:
        raise ValueError("{} tombstones match — disambiguate with --guid, --sid or --rid "
                         "(same-named tombstones are NOT interchangeable)".format(len(cands)))
    return cands[0], cands


# --------------------------------------------------------------------------- identity helpers


def domain_from_base(base):
    """'DC=corp,DC=local' -> 'corp.local'."""
    parts = [p.strip() for p in (base or "").split(",")]
    dcs = [p.split("=", 1)[1] for p in parts if p.upper().startswith("DC=") and "=" in p]
    return ".".join(dcs)


def bind_user(user, base, domain=None):
    """A bare sAMAccountName does NOT bind against AD — it needs a UPN or DOMAIN\\\\user.

    So qualify it: 'jdoe' + base 'DC=corp,DC=local' -> 'jdoe@corp.local'.
    """
    user = (user or "").strip()
    if not user or "\\" in user or "@" in user:
        return user
    dom = domain or domain_from_base(base)
    return "{}@{}".format(user, dom) if dom else user


# --------------------------------------------------------------------------- LDAP layer


def connect(args):
    """ldap3 is imported lazily so the pure helpers above stay importable without it."""
    try:
        import ldap3
        from ldap3 import Server, Connection
    except ImportError:
        sys.exit("ldap3 is required:  pip install ldap3")

    tls = None
    if getattr(args, "insecure", False):
        from ldap3 import Tls
        tls = Tls(validate=0)

    server = Server(args.host,
                    port=args.port or (636 if args.ldaps else 389),
                    use_ssl=bool(args.ldaps),
                    tls=tls,
                    get_info=None,
                    connect_timeout=args.timeout)
    conn_args = dict(user=bind_user(args.user, args.base, getattr(args, "domain", None)),
                     password=args.password,
                     auto_bind=True,
                     receive_timeout=args.timeout)
    try:
        conn = Connection(server, **conn_args)
    except Exception as exc:                              # LDAPBindError and friends
        sys.exit("bind failed ({}): {}\n"
                 "  - AD simple bind needs 'user@corp.local' or 'CORP\\\\user' "
                 "(a bare sAMAccountName is rejected; the tool appends @domain from --base)\n"
                 "  - over plain LDAP some hardened domains refuse simple binds: add --ldaps\n"
                 "  - check the account is not locked/expired".format(
                     conn_args["user"], type(exc).__name__))
    if args.starttls and not args.ldaps:
        conn.start_tls()
    return conn


def _controls():
    # ldap3 accepts controls as (oid, criticality, value) tuples
    return [(SHOW_DELETED_OID, True, None)]


def list_tombstones(args):
    conn = connect(args)
    conn.search(args.base, DELETED_FILTER, attributes=ATTRS,
                search_scope="SUBTREE", controls=_controls())
    rows = []
    for entry in conn.entries:
        a = entry.entry_attributes_as_dict

        def one(key, default=""):
            v = a.get(key)
            if isinstance(v, list):
                v = v[0] if v else None
            return default if v is None else v

        rows.append({
            "dn": str(entry.entry_dn),
            "raw_name": str(one("name")),
            "name": clean_deleted_name(one("name")),
            "sam": clean_deleted_name(one("sAMAccountName")) or clean_deleted_name(one("name")),
            "guid": guid_to_str(one("objectGUID")),
            "sid": sid_to_str(one("objectSid")),
            "rid": sid_rid(sid_to_str(one("objectSid"))),
            "last_known_parent": str(one("lastKnownParent")),
            "last_known_rdn": str(one("msDS-LastKnownRDN")),
            "when_changed": str(one("whenChanged")),
            "uac": one("userAccountControl"),
            "classes": [str(c) for c in (a.get("objectClass") or [])],
            "description": str(one("description")),
        })
    # the search returns the 'CN=Deleted Objects' container too — it is not a tombstone
    return [r for r in rows if is_tombstone(r)]


def print_table(rows):
    if not rows:
        print("(no deleted objects returned — check --base, bind rights, and that the Recycle Bin is enabled)")
        return
    hdr = "{:<3} {:<26} {:<7} {:<36} {:<10} {}".format("#", "name", "RID", "GUID", "SID?", "lastKnownParent")
    print(hdr)
    print("-" * len(hdr))
    for i, t in enumerate(rows, 1):
        print("{:<3} {:<26} {:<7} {:<36} {:<10} {}".format(
            i,
            (t["name"] or t["sam"])[:26],
            "None" if t["rid"] is None else t["rid"],
            t["guid"],
            "no" if not t["sid"] else "yes",
            t["last_known_parent"] or "-"))


def cmd_list(args):
    rows = list_tombstones(args)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    rows = match_tombstones(rows, guid=args.guid, sid=args.sid, rid=args.rid,
                            name=args.name, last_known_parent=args.last_known_parent)
    print_table(rows)
    return 0


def cmd_restore(args):
    rows = list_tombstones(args)
    try:
        chosen, cands = select(rows, guid=args.guid, sid=args.sid, rid=args.rid,
                               name=args.name, last_known_parent=args.last_known_parent)
    except ValueError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        print_table(rows)                      # show what there was to choose from
        return 2

    if len(cands) > 1:
        print_table(cands)

    print("selected: {}  (GUID {}, RID {})".format(chosen["name"], chosen["guid"], chosen["rid"]))
    print("tombstone DN: {!r}".format(chosen["dn"]))
    print("lastKnownParent: {}".format(chosen["last_known_parent"]))

    try:
        new_dn = restored_dn(chosen, args.new_name, args.new_parent)
    except ValueError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 2
    print("restore DN: {}".format(new_dn))

    if not args.apply:
        print("\n[dry-run] add --apply to perform the restore. AD restores an object with a modify that\n"
              "    REPLACE distinguishedName = <restore DN>\n"
              "    DELETE  isDeleted\n"
              "  sent against the tombstone DN with the SHOW_DELETED control (critical).\n"
              "  NB: 'isDeleted=FALSE' alone is NOT accepted — AD answers unwillingToPerform.")
        return 0

    from ldap3 import MODIFY_REPLACE, MODIFY_DELETE
    conn = connect(args)
    ok = conn.modify(chosen["dn"],
                     {"distinguishedName": [(MODIFY_REPLACE, [new_dn])],
                      "isDeleted": [(MODIFY_DELETE, [])]},
                     controls=_controls())
    print("\nmodify result: {}  {}".format(ok, conn.result.get("description")))
    if not ok:
        print("hint: unwillingToPerform means the modify shape is wrong (it must move the DN, not just "
              "flip isDeleted); noSuchObject means the tombstone DN was mangled in transit; "
              "check the Reanimate-Tombstones right if it is accessDenied.", file=sys.stderr)
        return 1

    # verify: the object should now be visible without the SHOW_DELETED control
    lookup = args.new_name or chosen["sam"] or chosen["name"]
    conn.search(args.base, "(sAMAccountName={})".format(lookup),
                attributes=["distinguishedName", "sAMAccountName"])
    names = [str(e.entry_dn) for e in conn.entries]
    if names:
        print("verified restored: {}".format(", ".join(names)))
    elif args.new_name:
        conn.search(args.base, "(cn={})".format(lookup), attributes=["distinguishedName"])
        print("verified restored: {}".format(", ".join(str(e.entry_dn) for e in conn.entries)) or
              "not found by name — check its new parent")
    else:
        print("restore reported OK but the object was not found by name — check its new parent")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="reanimate",
        description="List and restore AD objects deleted into the Recycle Bin (over LDAP, from Linux).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-H", "--host", required=True, help="DC hostname or IP")
        sp.add_argument("-u", "--user", required=True,
                        help="user@domain, DOMAIN\\\\user, or a bare sAMAccountName "
                             "(qualified with @<domain from --base>)")
        sp.add_argument("--domain", help="override the domain appended to a bare username")
        sp.add_argument("-p", "--password", required=True)
        sp.add_argument("--base", required=True, help="domain NC, e.g. 'DC=corp,DC=local'")
        sp.add_argument("--ldaps", action="store_true", help="use LDAPS (636)")
        sp.add_argument("--starttls", action="store_true")
        sp.add_argument("--port", type=int)
        sp.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
        sp.add_argument("--timeout", type=int, default=20)
        sp.add_argument("--guid")
        sp.add_argument("--sid")
        sp.add_argument("--rid", type=int)
        sp.add_argument("--name", help="CN/sAMAccountName (may be ambiguous)")
        sp.add_argument("--last-known-parent")

    sp = sub.add_parser("list", help="enumerate the Recycle Bin")
    common(sp)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("restore", help="restore one object (dry-run unless --apply)")
    common(sp)
    sp.add_argument("--apply", action="store_true", help="actually write (default: dry-run)")
    sp.add_argument("--new-name", help="rename the object while restoring it (RDN + name/SPN/UPN)")
    sp.add_argument("--new-parent", help="restore into this container instead of the last-known parent")
    sp.set_defaults(func=cmd_restore)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.guid and not args.sid and args.rid is None and not args.name \
            and not args.last_known_parent:
        print("note: no selector given — every matching tombstone will be shown; "
              "restore will refuse to guess.", file=sys.stderr)
    if not args.base:
        args.base = "CN=Deleted Objects"
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
