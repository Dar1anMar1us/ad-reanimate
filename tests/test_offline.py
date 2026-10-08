#!/usr/bin/env python3
"""
Offline tests for the pure logic in reanimate.py — no directory, no ldap3, no network.

Run:  python3 tests/test_offline.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import reanimate as R  # noqa: E402

FAILS = []


def check(label, got, want):
    if got == want:
        print("  ok   {:<48} {}".format(label, got))
    else:
        print("  FAIL {:<48} got={!r} want={!r}".format(label, got, want))
        FAILS.append(label)


# ── SID decoding (bytes as AD returns objectSid) ────────────────────────────────
SID_BASE = bytes([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]) + \
           (1392491010).to_bytes(4, "little") + (1358638721).to_bytes(4, "little")


def sid_bytes(rid):
    return SID_BASE + (2126982587).to_bytes(4, "little") + rid.to_bytes(4, "little")


print("SID decoding")
check("rid 1111 -> full SID",
      R.sid_to_str(sid_bytes(1111)),
      "S-1-5-21-1392491010-1358638721-2126982587-1111")
check("sid_rid()", R.sid_rid(sid_bytes(1111)), 1111)
check("sid_rid() on a string", R.sid_rid("S-1-5-21-1-2-3-500"), 500)
check("None -> ''", R.sid_to_str(None), "")
check("string passes through", R.sid_to_str("S-1-5-21-9-9-9-1111"), "S-1-5-21-9-9-9-1111")
check("well-known S-1-5-32 (Builtin)",
      R.sid_to_str(bytes([1, 1, 0, 0, 0, 0, 0, 5]) + (32).to_bytes(4, "little")), "S-1-5-32")

# ── GUID decoding (objectGUID is little-endian mixed) ──────────────────────────
# Real value from a live DC: ldapsearch showed objectGUID:: w4KBkwu/CkGaqkXI4aAuvw==
# for the tombstone 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
print("GUID decoding")
import base64  # noqa: E402
check("bytes_le -> canonical",
      R.guid_to_str(base64.b64decode("w4KBkwu/CkGaqkXI4aAuvw==")),
      "938182c3-bf0b-410a-9aaa-45c8e1a02ebf")
check("non-16-byte input -> hex", R.guid_to_str(b"\x01\x02"), "0102")
check("string passes through, braces stripped",
      R.guid_to_str("{8B3F8193-BF0B-410A-AA45-C8E1A02EBF}"),
      "8b3f8193-bf0b-410a-aa45-c8e1a02ebf")

# ── tombstone DN form ─────────────────────────────────────────────────────────
print("tombstone DN")
check("separator is 0x0A",
      R.tombstone_dn("cert_admin", "8b3f8193-bf0b-410a-aa45-c8e1a02ebf"),
      "CN=cert_admin\nDEL:8b3f8193-bf0b-410a-aa45-c8e1a02ebf,CN=Deleted Objects")

# ── matching + the ambiguity guard (the expensive mistake this tool prevents) ──
print("matching")
BIN = [
    {"name": "cert_admin", "sam": "cert_admin", "guid": "aaa", "sid": R.sid_to_str(sid_bytes(1109)),
     "last_known_parent": "OU=ADCS,DC=corp,DC=local"},
    {"name": "cert_admin", "sam": "cert_admin", "guid": "bbb", "sid": R.sid_to_str(sid_bytes(1110)),
     "last_known_parent": "OU=ADCS,DC=corp,DC=local"},
    {"name": "cert_admin", "sam": "cert_admin", "guid": "ccc", "sid": R.sid_to_str(sid_bytes(1111)),
     "last_known_parent": "OU=ADCS,DC=corp,DC=local"},
    {"name": "old_pc", "sam": "old_pc$", "guid": "ddd", "sid": R.sid_to_str(sid_bytes(1200)),
     "last_known_parent": "CN=Computers,DC=corp,DC=local"},
]

check("name matches all three", len(R.match_tombstones(BIN, name="cert_admin")), 3)
check("by rid", [t["guid"] for t in R.match_tombstones(BIN, rid=1111)], ["ccc"])
check("by full sid",
      [t["guid"] for t in R.match_tombstones(BIN, sid=R.sid_to_str(sid_bytes(1111)))], ["ccc"])
check("by guid", [t["name"] for t in R.match_tombstones(BIN, guid="ddd")], ["old_pc"])
check("by last_known_parent (case/space tolerant)",
      len(R.match_tombstones(BIN, last_known_parent="ou=adcs,dc=CORP,dc=local")), 3)
check("combined name + parent + rid",
      [t["guid"] for t in R.match_tombstones(
          BIN, name="cert_admin", last_known_parent="OU=ADCS,DC=corp,DC=local", rid=1110)], ["bbb"])

try:
    R.select(BIN, name="cert_admin")
    check("ambiguous select raises", "no exception", "ValueError")
except ValueError as exc:
    check("ambiguous select raises", "ValueError" if "3 tombstones" in str(exc) else str(exc),
          "ValueError")

chosen, _ = R.select(BIN, rid=1111)
check("unambiguous select", chosen["guid"], "ccc")

try:
    R.select(BIN, name="does_not_exist")
    check("empty select raises", "no exception", "ValueError")
except ValueError:
    check("empty select raises", "ValueError", "ValueError")

# ── identity handling (a bare sAMAccountName is rejected by AD simple bind) ─────
print("identity")
check("domain from base", R.domain_from_base("DC=corp,DC=local"), "corp.local")
check("bare name -> UPN", R.bind_user("jdoe", "DC=corp,DC=local"), "jdoe@corp.local")
check("UPN untouched", R.bind_user("jdoe@corp.local", "DC=corp,DC=local"), "jdoe@corp.local")
check("DOMAIN\\user untouched", R.bind_user("CORP\\jdoe", "DC=corp,DC=local"), "CORP\\jdoe")
check("--domain override", R.bind_user("jdoe", "DC=corp,DC=local", "other.tld"), "jdoe@other.tld")
check("machine account", R.bind_user("WS01$", "DC=tombwatcher,DC=htb"), "WS01$@tombwatcher.htb")

# ── tombstone name munging (real values from a live DC) ────────────────────────
print("tombstone names")
check("strip the DEL suffix from name",
      R.clean_deleted_name("cert_admin\nDEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf"), "cert_admin")
check("plain name untouched", R.clean_deleted_name("cert_admin"), "cert_admin")
check("empty", R.clean_deleted_name(None), "")
check("container is not a tombstone", R.is_tombstone({"raw_name": "Deleted Objects"}), False)
check("real tombstone detected",
      R.is_tombstone({"raw_name": "cert_admin\nDEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf"}), True)
BIN_CLEAN = [dict(t, raw_name=t["name"] + "\nDEL:" + t["guid"]) for t in BIN]
check("--name matches after cleaning",
      [t["guid"] for t in R.match_tombstones(BIN_CLEAN, name="cert_admin")], ["aaa", "bbb", "ccc"])

# ── restore DN (a restore moves the DN; it is not 'isDeleted=FALSE') ───────────
print("restore DN")
ROW = {"raw_name": "cert_admin\nDEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf",
       "last_known_rdn": "cert_admin", "last_known_parent": "OU=ADCS,DC=corp,DC=local"}
check("from last-known RDN + parent", R.restored_dn(ROW), "CN=cert_admin,OU=ADCS,DC=corp,DC=local")
check("full RDN form kept", R.restored_dn(dict(ROW, last_known_rdn="OU=Other")),
      "OU=Other,OU=ADCS,DC=corp,DC=local")
check("falls back to the cleaned name",
      R.restored_dn({"raw_name": "old_ws\nDEL:abc", "last_known_parent": "CN=Computers,DC=corp,DC=local"}),
      "CN=old_ws,CN=Computers,DC=corp,DC=local")
check("--new-name overrides the RDN", R.restored_dn(ROW, new_name="restored_me"),
      "CN=restored_me,OU=ADCS,DC=corp,DC=local")
check("--new-parent redirects", R.restored_dn(ROW, new_parent="OU=Elsewhere,DC=corp,DC=local"),
      "CN=cert_admin,OU=Elsewhere,DC=corp,DC=local")
try:
    R.restored_dn({"raw_name": "x\nDEL:g"})
    check("missing parent refuses", "no exception", "ValueError")
except ValueError:
    check("missing parent refuses", "ValueError", "ValueError")

# ── CLI surface ───────────────────────────────────────────────────────────────
print("CLI")
p = R.build_parser()
a = p.parse_args(["list", "-H", "dc", "-u", "u", "-p", "p", "--base", "DC=corp,DC=local"])
check("list parses", a.func.__name__, "cmd_list")
check("json default off", a.json, False)
b = p.parse_args(["restore", "-H", "dc", "-u", "u", "-p", "p", "--base", "DC=corp,DC=local",
                  "--rid", "1111"])
check("restore is dry-run by default", b.apply, False)
check("rid parsed as int", b.rid, 1111)

print()
if FAILS:
    print("{} FAILED: {}".format(len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all offline checks passed")
