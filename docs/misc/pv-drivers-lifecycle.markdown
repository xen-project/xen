# Xen PV Drivers lifecycle

## Purpose

Getting new PV drivers accepted in Xen, upstream code bases, and ABI
stable in the quickest and most efficient way possible.


## Design Phase

The first step toward acceptance of a new PV protocol is to write a
design document and send it to xen-devel. It should cover the xenstore
handshake mechanism, the ABI, how the protocol works and anything else
which is required to write an implementation of it. The usage of C-like
structs to describe language and platform agnostic protocols is
discouraged.

An attempt should be made to design the ABI such that it will be OS
agnostic, that future versions will not need to introduce
backward-incompatible changes, and so on; but these are not yet hard
requirements.

After the high level design of the protocol has been discussed and
agreed, the document is committed to xen.git.


## Prototype Stage

The contributor sends patches to implement the PV drivers for the new
protocol to the relevant open source mailing lists, such as LKML,
qemu-devel and xen-devel.

The code is expected to work, be good quality and faithfully implement
the spec. However, there are no promises about ABI and cross-platform
compatibility yet.

After careful review by the relevant maintainers, the code is committed
to the upstream code bases. The drivers are considered experimental.


## Production Stage

The quality of the drivers and the spec is improved. Bugs are fixed.
The protocol version is likely bumped. More testing leads to confidence
that the spec and the drivers are ready for production usage. Promises
about backward compatibility and cross-platform compatibility are
clearly spelled out.


## How to move forward from a stage to the next

The PV protocols Czar is responsible for determining the transitions
between stages. Our governance principles specify "lazy consensus" for
most things. It applies to this case too. New PV protocols should move
from one stage to the next within a reasonable time frame unless someone
has specific technical objections and voices them in a responsive
manner.
