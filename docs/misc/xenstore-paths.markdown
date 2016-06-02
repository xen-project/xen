# XenStore Paths

This document attempts to defines all the paths which are in common
use by either guests, front-/back-end drivers, toolstacks etc.

The XenStore wire protocol itself is described in
[xenstore.txt](xenstore.txt).

## Notation

This document is intended to be partially machine readable, such that
test system etc can use it to validate whether the xenstore paths used
by a test are allowable etc.

Therefore the following notation conventions apply:

A xenstore path is generically defined as:

        PATH = VALUES [TAGS]

        PATH/* [TAGS]

The first syntax defines a simple path with a single value. The second
syntax defines an aggregated set of paths which are usually described
externally to this document. The text will give a pointer to the
appropriate external documentation.

PATH can contain simple regex constructs following the Perl compatible
regexp syntax described in pcre(3) or perlre(1). In addition the
following additional wild card names are defined and are evaluated
before regexp expansion:

* ~ -- expands to an arbitrary a domain's home path (described below).
  Only valid at the begining of a path.
* $DEVID -- a per-device type device identifier. Typically an integer.
* $DOMID -- a domain identifier, an integer. Typically this refers to
  the "other" domain. i.e. ~ refers to the domain providing a service
  while $DOMID is the consumer of that service.
* $UUID -- a UUID in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
* $INDEX -- an integer used as part of a path when listing a set of
            values. Typically these integers are contiguous.

VALUES are strings and can take the following forms:

* PATH -- a XenStore path.
* STRING -- an arbitrary string.
* INTEGER -- An integer, in decimal representation unless otherwise
  noted.
 * MEMKB -- the decimal representation of a number of kilobytes.
 * EVTCHN -- the decimal representation of an event channel.
 * GNTREF -- the decimal representation of a grant reference.
* "a literal string" -- literal strings are contained within quotes.
* (VALUE | VALUE | ... ) -- a set of alternatives. Alternatives are
  separated by a "|" and all the alternatives are enclosed in "(" and
  ")".
* DISTRIBUTION -- information about a software distribution, comprised
                  of 3 or 4 space separated UTF-8 strings as follows:

                  VENDOR -- Commonly used vendor short name,
                            e.g "Citrix" rather than "Citrix Systems
                            Inc."

                  PRODUCT -- Commonly used product (e.g. driver) name
                             without version information.

                  If the toolstack needs to match on either of the above
                  values it should support Unix glob style matching.

                  VERSION -- A version number that will sort properly
                             under coreutils version sorting (sort -V)
                             rules.

                  ATTRIBUTES -- Optional human readable text to denote
                                attributes of the software, e.g. "debug".
                                This text is freeform and no meaning
                                should be inferred. It is intended for
                                display purposes only.

* MAC_ADDRESS -- 6 integers, in hexadecimal form, separated by ':',
                 specifying an IEEE 802.3 ethernet MAC address.
* IPV4_ADDRESS -- 4 integers, in decimal form, separated by '.',
                  specifying an IP version 4 address as described
                  IETF RFC 791.
* IPV6_ADDRESS -- Up to 8 integers, in hexadecimal form, separated
                  by ':', specifying an IP version 6 address as
                  described in IETF RFC 4291.

Additional TAGS may follow as a comma separated set of the following
tags enclosed in square brackets.

* w -- Path is writable by the containing domain, that is the domain
  whose home path ~ this key is under or which /vm/$UUID refers to. By
  default paths under both of these locations are read only for the
  domain.
* n -- Path is neither readable nor writeable for guest domains.
* HVM -- Path is valid for HVM domains only
* PV --  Path is valid for PV domains only
* BACKEND -- Path is valid for a backend domain (AKA driver domain)
* INTERNAL -- Although a path is visible to the domain its use is
  reserved for the virtual firmware or Xen platform code. Guest
  Operating Systems must not read this key or otherwise rely on its
  presence or contents.
* DEPRECATED -- This path is deprecated and may be removed in its
  current form in the future. Guests should not add new dependencies
  on such paths.

Owning domain means the domain whose home path this tag is found
under.

Lack of either a __HVM__ or __PV__ tag indicates that the path is
valid for either type of domain (including PVonHVM and similar mixed
domain types).

## Domain Home Path

Every domain has a home path within the xenstore hierarchy. This is
the path where the majority of the domain-visible information about
each domain is stored.

This path is:

      /local/domain/$DOMID

All non-absolute paths are relative to this path.

Although this path could be considered a "Home Directory" for the
domain it would not usually be writable by the domain. The tools will
create writable subdirectories as necessary.

## Per Domain Paths

## General Paths

#### ~/vm = PATH []

A pointer back to the domain's /vm/$UUID path (described below).

#### ~/name = STRING []

The guests name.

#### ~/domid = INTEGER   []

The domain's own ID.

#### ~/image/device-model-pid = INTEGER   [INTERNAL]

The process ID of the device model associated with this domain, if it
has one.

#### ~/cpu/[0-9]+/availability = ("online"|"offline") [PV]

One node for each virtual CPU up to the guest's configured
maximum. Valid values are "online" and "offline". The guest is expected to react to changes in this path by bringing the appropriate VCPU on or offline using the VCPUOP interface described in [xen/include/public/vcpu.h][VCPU]

This protocol is not currently well documented.

#### ~/memory/static-max = MEMKB []

Specifies a static maximum amount memory which this domain should
expect to be given. In the absence of in-guest memory hotplug support
this set on domain boot and is usually the maximum amount of RAM which
a guest can make use of. See [docs/misc/libxl_memory.txt][LIBXLMEM]
for a description of how memory is accounted for in toolstacks using
the libxl library.

#### ~/memory/target = MEMKB []

The current balloon target for the domain. The balloon driver within
the guest is expected to make every effort to every effort use no more
than this amount of RAM.

#### ~/memory/videoram = MEMKB [HVM,INTERNAL]

The size of the video RAM this domain is configured with.

#### ~/device/suspend/event-channel = ""|EVTCHN [w]

The domain's suspend event channel. The toolstack will create this
path with an empty value which the guest may choose to overwrite.

If the guest overwrites this, it will be with the number of an unbound
event channel port it has acquired.  The toolstack is expected to use
an interdomain bind, and then, when it wishes to ask the guest to
suspend, to signal the event channel.

The guest does not need to explicitly acknowledge the request; indeed,
there is no explicit signalling by the guest in the reverse direction.
The guest, when it is ready, simply shuts down (`SCHEDOP_shutdown`)
with reason code `SHUTDOWN_suspend`.  The toolstack is expected to use
`XEN_DOMCTL_subscribe` to be alerted to guest state changes, and
`XEN_SYSCTL_getdomaininfolist` to verify that the domain has
suspended.

Note that the use of this event channel suspend protocol is optional
for both sides.  By writing a non-empty string to the node, the guest
is advertising its support.  However, the toolstack is at liberty to
use the xenstore-based protocol instead (see ~/control/shutdown,
below) even if the guest has advertised support for the event channel
protocol.

#### ~/hvmloader/allow-memory-relocate = ("1"|"0") [HVM,INTERNAL]

If the default low MMIO hole (below 4GiB) is not big enough for all
the devices, this indicates if hvmloader should relocate guest memory
into the high memory region (above 4GiB).  If "1", hvmloader will
relocate memory as needed, until 2GiB is reached; if "0", hvmloader
will not relocate guest memory.

#### ~/hvmloader/bios = ("rombios"|"seabios"|"OVMF") [HVM,INTERNAL]

The BIOS used by this domain.

#### ~/platform/* = ("0"|"1") [HVM,INTERNAL]

Various boolean platform properties.

* acpi -- is ACPI enabled for this domain
* acpi_s3 -- is ACPI S3 support enabled for this domain
* acpi_s4 -- is ACPI S4 support enabled for this domain

#### ~/platform/generation-id = INTEGER ":" INTEGER [HVM,INTERNAL]

The lower and upper 64-bit words of the 128-bit VM Generation ID.

This key is used by hvmloader to create the ACPI VM Generation ID
device.  It initialises a 16 octet region of guest memory with this
value.  The guest physical address of this region is saved in the
HVM_PARAM_VM_GENERATION_ID_ADDR HVM parameter.

If this key is not present, is empty, or is all-zeros ("0:0") then the
ACPI device is not created.

When restoring a guest, the toolstack may (in certain circumstances)
need generate a new random generation ID and write it to guest memory
at the guest physical address in HVM_PARAM_VM_GENERATION_ID_ADDR.

See Microsoft's "Virtual Machine Generation ID" specification for the
circumstances where the generation ID needs to be changed.

### Frontend device paths

Paravirtual device frontends are generally specified by their own
directory within the XenStore hierarchy. Usually this is under
~/device/$TYPE/$DEVID although there are exceptions, e.g. ~/console
for the first PV console.

#### ~/device/vbd/$DEVID/* []

A virtual block device frontend. Described by
[xen/include/public/io/blkif.h][BLKIF]

#### ~/device/vfb/$DEVID/* []

A virtual framebuffer frontend. Described by
[xen/include/public/io/fbif.h][FBIF]

#### ~/device/vkbd/$DEVID/* []

A virtual keyboard device frontend. Described by
[xen/include/public/io/kbdif.h][KBDIF]

#### ~/device/vif/$DEVID/* []

A virtual network device frontend. Described by
[xen/include/public/io/netif.h][NETIF]

#### ~/device/vscsi/$DEVID/* []

A virtual scsi device frontend. Described by
[xen/include/public/io/vscsiif.h][SCSIIF]

#### ~/device/vusb/$DEVID/* []

A virtual usb device frontend. Described by
[xen/include/public/io/usbif.h][USBIF]

#### ~/console/* []

The primary PV console device. Described in [console.txt](console.txt)

#### ~/device/console/$DEVID/* []

A secondary PV console device. Described in [console.txt](console.txt)

#### ~/serial/$DEVID/* [HVM]

An emulated serial device. Described in [console.txt](console.txt)

#### ~/store/port = EVTCHN [DEPRECATED]

The event channel used by the domain's connection to XenStore.

This path is deprecated since the same information is provided via the
[start_info][SI] for PV guests and as an [HVM param][HVMPARAMS] for
HVM guests. There is an obvious chicken and egg problem with
extracting this value from xenstore in order to setup the xenstore
communication ring.

#### ~/store/ring-ref = GNTREF [DEPRECATED]

The grant reference of the domain's XenStore ring.

As with ~/store/port this path is deprecated.

### Backend Device Paths

Paravirtual device backends are generally specified by their own
directory within the XenStore hierarchy. Usually this is under
~/backend/$TYPE/$DOMID/$DEVID.

#### ~/backend/vbd/$DOMID/$DEVID/* []

A virtual block device backend. Described by
[xen/include/public/io/blkif.h][BLKIF]

Uses the in-kernel blkback driver.

#### ~/backend/qdisk/$DOMID/$DEVID/* []

A virtual block device backend. Described by
[xen/include/public/io/blkif.h][BLKIF]

Uses the qemu based disk backend.

#### ~/backend/tap/$DOMID/$DEVID/* []

A virtual block device backend. Described by
[xen/include/public/io/blkif.h][BLKIF]

Uses the in-kernel blktap (v1) disk backend (deprecated).

#### ~/backend/vfb/$DOMID/$DEVID/* []

A virtual framebuffer backend. Described by
[xen/include/public/io/fbif.h][FBIF]

#### ~/backend/vkbd/$DOMID/$DEVID/* []

A virtual keyboard device backend. Described by
[xen/include/public/io/kbdif.h][KBDIF]

#### ~/backend/vif/$DOMID/$DEVID/* []

A virtual network device backend. Described by
[xen/include/public/io/netif.h][NETIF]

#### ~/backend/vscsi/$DOMID/$DEVID/* []

A PV SCSI backend.

#### ~/backend/vusb/$DOMID/$DEVID/* []

A PV USB backend. Described by
[xen/include/public/io/usbif.h][USBIF]

#### ~/backend/console/$DOMID/$DEVID/* []

A PV console backend. Described in [console.txt](console.txt)

#### ~/backend/qusb/$DOMID/$DEVID/* []

A PV USB device backend. Described by
[xen/include/public/io/usbif.h][USBIF]

Uses the qemu based USB backend.

#### ~/device-model/$DOMID/* [INTERNAL]

Information relating to device models running in the domain. $DOMID is
the target domain of the device model.

#### ~/libxl/disable_udev = ("1"|"0") []

Indicates whether device hotplug scripts in this domain should be run
by udev ("0") or will be run by the toolstack directly ("1").

### Platform Feature and Control Paths

#### ~/control/shutdown = (""|COMMAND) [w]

This is the PV shutdown control node. A toolstack can write various
commands here to cause various guest shutdown, reboot or suspend
activities. The guest acknowledges a request by writing the empty
string back to the command node.

The precise protocol is not yet documented.

#### ~/control/feature-poweroff = (""|"0"|"1") [w]
#### ~/control/feature-reboot = (""|"0"|"1") [w]
#### ~/control/feature-suspend = (""|"0"|"1") [w]

These may be initialized to "" by the toolstack and may then be set
to 0 or 1 by a guest to indicate whether it is capable or incapable,
respectively, of responding to the corresponding command when written
to ~/control/shutdown.
A toolstack may then sample the feature- value at the point of issuing
a PV control command and respond accordingly:

"0" -> the frontend should not be expected to respond, so fail the
       control operation
"1" -> the frontend should be expected to respond, so wait for it to
       do so and maybe fail the control operation after some reasonable
       timeout.
""  -> the frontend may or may not respond, so wait for it to do so and
       then maybe try an alternative control mechanism after some
       reasonable timeout.

Since a toolstack may not initialize these paths, and the parent
~/control path is read-only to a guest, a guest should not expect a
write to succeed. If it fails the guest may log the failure but should
continue to process the corresponding command when written to
~/control/shutdown regardless.

#### ~/control/feature-s3 = (""|"0"|"1") [w,HVM]
#### ~/control/feature-s4 = (""|"0"|"1") [w,HVM]

These purpose of these feature flags is identical to feature-poweroff,
feature-reboot and feature-suspend above but concern triggering the
S3 or S4 power states of HVM guests.
A toolstack may create these values, but should not sample them unless
the corresponding acpi_ feature flag is set in ~/platform.

#### ~/control/platform-feature-multiprocessor-suspend = (0|1) []

Indicates to the guest that this platform supports the multiprocessor
suspend feature.

#### ~/control/platform-feature-xs\_reset\_watches = (0|1) []

Indicates to the guest that this platform supports the
XS_RESET_WATCHES xenstore message. See
[xen/include/public/io/xs\_wire.h][XSWIRE] for the XenStore wire
protocol definition.

### Domain Controlled Paths

#### ~/data/* [w]

A domain writable path. Available for arbitrary domain use.

#### ~/drivers/$INDEX = DISTRIBUTION [w]

A domain may write information about installed PV drivers using
paths of this form.

#### ~/feature/hotplug/vif = ("0"|"1") [w]
#### ~/feature/hotplug/vbd = ("0"|"1") [w]

By setting these paths to "1" a guest can indicate to a toolstack
that it is capable of responding immediately to instantiation of,
respectively, new vif by bringing online a new PV network device or
a new vbd by bringing online a new PV block device.
If the guest sets this path to "0" then it is indicating that it is
definitely unable to respond immediately and hence the toolstack should
defer instantiaton to the next VM start. However, if the path is absent
then the toolstack may attempt the operation.

#### ~/attr/vif/$DEVID/name = STRING [w]

A domain may write its internal 'friendly' name for a network device
using this path using UTF-8 encoding. A toolstack or UI may use this
for display purposes. No particular meaning should be inferred from the
name.

#### ~/attr/vif/$DEVID/mac/$INDEX = MAC_ADDRESS [w]

Paths of this form may be written by the guest to indicate MAC addresses
it is currently using. These may be multicast or unicast addresses. For
any of the paths the value of $INDEX is arbitrary.
The values written are primarily for display purposes and must not be used
for packet filtering or routing purposes.

#### ~/attr/vif/$DEVID/ipv4/$INDEX = IPV4_ADDRESS [w]
#### ~/attr/vif/$DEVID/ipv6/$INDEX = IPV6_ADDRESS [w]

Paths of this form may be written by the guest to indicate IP addresses
in use by the stack bound to the network frontend. For any of the paths
the value of $INDEX is arbitrary.
The values written are primarily for display purposes and must not be used
for packet filtering or routing purposes. A toolstack may attempt to use an
address written in one of these paths to, for example, establish a VNC
session to the guest (although clearly some level of trust is placed
in the value supplied by the guest in this case).

### Paths private to the toolstack

#### ~/device-model/$DOMID/state [w]

Contains the status of the device models running on the domain.

#### ~/device-model/$DOMID/backends/* [w]

Backend types the device model is supporting. Each entry below backends
is a directory which may contain further nodes specific to the backend
type. The name of each backend directory is the same as the backend type
(e.g. "qdisk").

#### ~/libxl/$DOMID/qdisk-backend-pid [w]

Contains the PIDs of the device models running on the domain.

## Virtual Machine Paths

The /vm/$UUID namespace is used by toolstacks to store various
information relating to the domain which is not intended to be guest
visible (hence they are all tagged [n,INTERNAL]).

Several of the keys here are not well defined and/or not well located
and are liable to be replaced with more fully defined paths in the
future.

### /vm/$UUID/uuid = UUID [n,INTERNAL]

Value is the same UUID as the path.

### /vm/$UUID/name = STRING [n,INTERNAL]

The domain's name.

### /vm/$UUID/image/* [n,INTERNAL]

Various information relating to the domain builder used for this guest.

### /vm/$UUID/start_time = INTEGER "." INTEGER [n,INTERNAL]

The time which the guest was started in SECONDS.MICROSECONDS format

### /vm/$UUID/rtc/timeoffset = ""|INTEGER [n,HVM,INTERNAL]

The guest's virtual time offset from UTC in seconds.

## Platform-Level paths

### libxl Specific Paths

#### /libxl/$DOMID/device/$KIND/$DEVID

Created by libxl for every frontend/backend pair created for $DOMID.
Used by libxl for enumeration and management of the device.

#### /libxl/$DOMID/device/$KIND/$DEVID/frontend

Path in xenstore to the frontend, normally
/local/domain/$DOMID/device/$KIND/$DEVID

#### /libxl/$DOMID/device/$KIND/$DEVID/backend

Path in xenstore to the backend, normally
/local/domain/$BACKEND_DOMID/backend/$KIND/$DOMID/$DEVID

#### /libxl/$DOMID/device/$KIND/$DEVID/$NODE

Trustworthy copy of /local/domain/$DOMID/backend/$KIND/$DEVID/$NODE.

#### /libxl/$DOMID/dm-version ("qemu\_xen"|"qemu\_xen\_traditional") = [n,INTERNAL]

The device model version for a domain.

#### /libxl/$DOMID/remus/netbuf/$DEVID/ifb = STRING [n,INTERNAL]

ifb device used by Remus to buffer network output from the associated vif.

### xenstored specific paths

The /tool/xenstored namespace is created by the xenstore daemon or domain
for the toolstack to obtain e.g. the domain id of a xenstore domain.

#### /tool/xenstored/domid = INTEGER [n,INTERNAL]

Domain Id of the xenstore domain in case xenstore is provided via a
domain instead of a daemon in dom0.

[BLKIF]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,blkif.h.html
[FBIF]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,fbif.h.html
[HVMPARAMS]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,hvm,params.h.html
[KBDIF]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,kbdif.h.html
[LIBXLMEM]: http://xenbits.xen.org/docs/unstable/misc/libxl_memory.txt
[NETIF]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,netif.h.html
[SCSIIF]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,vscsiif.h.html
[SI]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,xen.h.html#Struct_start_info
[USBIF]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,usbif.h.html
[VCPU]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,vcpu.h.html
[XSWIRE]: http://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,io,xs_wire.h.html
