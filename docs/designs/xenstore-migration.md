# Xenstore Migration

## Background

The design for *Non-Cooperative Migration of Guests*[1] explains that extra
save records are required in the migrations stream to allow a guest running
PV drivers to be migrated without its co-operation. Moreover the save
records must include details of registered xenstore watches as well as
content; information that cannot currently be recovered from `xenstored`,
and hence some extension to the xenstore protocol[2] will also be required.

The *libxenlight Domain Image Format* specification[3] already defines a
record type `EMULATOR_XENSTORE_DATA` but this is not suitable for
transferring xenstore data pertaining to the domain directly as it is
specified such that keys are relative to the path
`/local/domain/$dm_domid/device-model/$domid`. Thus it is necessary to
define at least one new save record type.

## Proposal

### New Save Record

A new mandatory record type should be defined within the libxenlight Domain
Image Format:

`0x00000007: DOMAIN_XENSTORE_DATA`

An arbitrary number of these records may be present in the migration
stream and may appear in any order. The format of each record should be as
follows:


```
    0       1       2       3       4       5       6       7    octet
+-------+-------+-------+-------+-------+-------+-------+-------+
| type                          | record specific data          |
+-------------------------------+                               |
...
+---------------------------------------------------------------+
```

where type is one of the following values


| Field  | Description                                      |
|--------|--------------------------------------------------|
| `type` | 0x00000000: invalid                              |
|        | 0x00000001: NODE_DATA                            |
|        | 0x00000002: WATCH_DATA                           |
|        | 0x00000003: TRANSACTION_DATA                     |
|        | 0x00000004 - 0xFFFFFFFF: reserved for future use |


and data is one of the record data formats described in the following
sections.


NOTE: The record data does not contain an overall length because the
libxenlight record header specifies the length.


**NODE_DATA**


Each NODE_DATA record specifies a single node in xenstore and is formatted
as follows:


```
    0       1       2       3     octet
+-------+-------+-------+-------+
| NODE_DATA                     |
+-------------------------------+
| path length                   |
+-------------------------------+
| path data                     |
...
| pad (0 to 3 octets)           |
+-------------------------------+
| perm count (N)                |
+-------------------------------+
| perm0                         |
+-------------------------------+
...
+-------------------------------+
| permN                         |
+-------------------------------+
| value length                  |
+-------------------------------+
| value data                    |
...
| pad (0 to 3 octets)           |
+-------------------------------+
```

where perm0..N are formatted as follows:


```
    0       1       2       3     octet
+-------+-------+-------+-------+
| perm  | pad   | domid         |
+-------------------------------+
```


path length and value length are specified in octets (excluding the NUL
terminator of the path). perm should be one of the ASCII values `w`, `r`,
`b` or `n` as described in [2]. All pad values should be 0.
All paths should be absolute (i.e. start with `/`) and as described in
[2].


**WATCH_DATA**


Each WATCH_DATA record specifies a registered watch and is formatted as
follows:


```
    0       1       2       3     octet
+-------+-------+-------+-------+
| WATCH_DATA                    |
+-------------------------------+
| wpath length                  |
+-------------------------------+
| wpath data                    |
...
| pad (0 to 3 octets)           |
+-------------------------------+
...
+-------------------------------+
| token length                  |
+-------------------------------+
| token data                    |
...
| pad (0 to 3 octets)           |
+-------------------------------+
```

wpath length and token length are specified in octets (excluding the NUL
terminator). The wpath should be as described for the `WATCH` operation in
[2]. The token is an arbitrary string of octets not containing any NUL
values.


**TRANSACTION_DATA**


Each TRANSACTION_DATA record specifies an open transaction and is formatted
as follows:


```
    0       1       2       3     octet
+-------+-------+-------+-------+
| TRANSACTION_DATA              |
+-------------------------------+
| tx_id                         |
+-------------------------------+
```

where tx_id is the non-zero identifier values of an open transaction.


### Protocol Extension

Before xenstore state is migrated it is necessary to wait for any pending
reads, writes, watch registrations etc. to complete, and also to make sure
that xenstored does not start processing any new requests (so that new
requests remain pending on the shared ring for subsequent processing on the
new host). Hence the following operation is needed:

```
QUIESCE                 <domid>|

Complete processing of any request issued by the specified domain, and
do not process any further requests from the shared ring.
```

The `WATCH` operation does not allow specification of a `<domid>`; it is
assumed that the watch pertains to the domain that owns the shared ring
over which the operation is passed. Hence, for the tool-stack to be able
to register a watch on behalf of a domain a new operation is needed:

```
ADD_DOMAIN_WATCHES      <domid>|<watch>|+

Adds watches on behalf of the specified domain.

<watch> is a NUL separated tuple of <path>|<token>. The semantics of this
operation are identical to the domain issuing WATCH <path>|<token>| for
each <watch>.
```

The watch information for a domain also needs to be extracted from the
sending xenstored so the following operation is also needed:

```
GET_DOMAIN_WATCHES      <domid>|<index>   <gencnt>|<watch>|*

Gets the list of watches that are currently registered for the domain.

<watch> is a NUL separated tuple of <path>|<token>. The sub-list returned
will start at <index> items into the the overall list of watches and may
be truncated (at a <watch> boundary) such that the returned data fits
within XENSTORE_PAYLOAD_MAX.

If <index> is beyond the end of the overall list then the returned sub-
list will be empty. If the value of <gencnt> changes then it indicates
that the overall watch list has changed and thus it may be necessary
to re-issue the operation for previous values of <index>.
```

To deal with transactions that were pending when the domain is migrated
it is necessary to start transactions with the same tx_id on behalf of the
domain in the receiving xenstored.

NOTE: For safety each such transaction should result in an `EAGAIN` when
the `TRANSACTION_END` operation is performed, as modifications made under
the tx_id will not be part of the migration stream.

The `TRANSACTION_START` operation does not allow specification of a
`<domid>`; it is assumed that the transaction pertains to the domain that
owns the shared ring over which the operation is passed. Neither does it
allow a `<transid>` to be specified; it is always chosen by xenstored.
Hence, for the tool-stack to be able to open a transaction on behalf of a
domain a new operation is needed:

```
START_DOMAIN_TRANSACTION    <domid>|<transid>|

Starts a transaction on behalf of a domain.

The semantics of this are similar to the domain issuing
TRANSACTION_START and receiving the specified <transid> as the response.
The main difference is that the transaction will be immediately marked as
'conflicting' such that when the domain issues TRANSACTION_END T|, it will
result in EAGAIN.
```

It may also be desirable to state in the protocol specification that
the `INTRODUCE` operation should not clear the `<gfn>` specified such that
a `RELEASE` operation followed by an `INTRODUCE` operation form an
idempotent pair. The current implementation of *C xentored* does this
(in the `domain_conn_reset()` function) but this could be dropped as this
behaviour is not currently specified and the page will always be zeroed
for a newly created domain.


* * *

[1] See https://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=docs/designs/non-cooperative-migration.md
[2] See https://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=docs/misc/xenstore.txt
[3] See https://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=docs/specs/libxl-migration-stream.pandoc
