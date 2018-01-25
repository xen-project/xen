# Intel Platform Shared Resource Monitoring/Control in xl

This document introduces Intel Platform Shared Resource Monitoring/Control
technologies, their basic concepts and the xl interfaces.

## Cache Monitoring Technology (CMT)

Cache Monitoring Technology (CMT) is a new feature available on Intel Haswell
and later server platforms that allows an OS or Hypervisor/VMM to determine
the usage of cache (currently only L3 cache supported) by applications running
on the platform. A Resource Monitoring ID (RMID) is the abstraction of the
application(s) that will be monitored for its cache usage. The CMT hardware
tracks cache utilization of memory accesses according to the RMID and reports
monitored data via a counter register.

For more detailed information please refer to Intel SDM chapter
"Platform Shared Resource Monitoring: Cache Monitoring Technology".

In Xen's implementation, each domain in the system can be assigned a RMID
independently, while RMID=0 is reserved for monitoring domains that don't
have CMT service attached. RMID is opaque for xl/libxl and is only used in
hypervisor.

### xl interfaces

A domain is assigned a RMID implicitly by attaching it to CMT service:

`xl psr-cmt-attach <domid>`

After that, cache usage for the domain can be shown by:

`xl psr-cmt-show cache-occupancy <domid>`

Once monitoring is not needed any more, the domain can be detached from the
CMT service by:

`xl psr-cmt-detach <domid>`

An attach may fail because of no free RMID available. In such case unused
RMID(s) can be freed by detaching corresponding domains from CMT service.

Maximum RMID and supported monitor types in the system can be obtained by:

`xl psr-hwinfo --cmt`

## Memory Bandwidth Monitoring (MBM)

Memory Bandwidth Monitoring(MBM) is a new hardware feature available on Intel
Broadwell and later server platforms which builds on the CMT infrastructure to
allow monitoring of system memory bandwidth. It introduces two new monitoring
event type to monitor system total/local memory bandwidth. The same RMID can
be used to monitor both cache usage and memory bandwidth at the same time.

For more detailed information please refer to Intel SDM chapter
"Overview of Cache Monitoring Technology and Memory Bandwidth Monitoring".

In Xen's implementation, MBM shares the same set of underlying monitoring
service with CMT and can be used to monitor memory bandwidth on a per domain
basis.

The xl interfaces are the same with that of CMT. The difference is the
monitor type is corresponding memory monitoring type (local-mem-bandwidth/
total-mem-bandwidth instead of cache-occupancy). E.g. after a `xl psr-cmt-attach`:

`xl psr-cmt-show local-mem-bandwidth <domid>`

`xl psr-cmt-show total-mem-bandwidth <domid>`

## Cache Allocation Technology (CAT)

Cache Allocation Technology (CAT) is a new feature available on Intel
Broadwell and later server platforms that allows an OS or Hypervisor/VMM to
partition cache allocation (i.e. L3/L2 cache) based on application priority or
Class of Service (COS). Each COS is configured using capacity bitmasks (CBM)
which represent cache capacity and indicate the degree of overlap and
isolation between classes. System cache resource is divided into numbers of
minimum portions which is then made up into subset for cache partition. Each
portion corresponds to a bit in CBM and the set bit represents the
corresponding cache portion is available.

For example, assuming a system with 8 portions and 3 domains:

 * A CBM of 0xff for every domain means each domain can access the whole cache.
   This is the default.

 * Giving one domain a CBM of 0x0f and the other two domain's 0xf0 means that
   the first domain gets exclusive access to half of the cache (half of the
   portions) and the other two will share the other half.

 * Giving one domain a CBM of 0x0f, one 0x30 and the last 0xc0 would give the
   first domain exclusive access to half the cache, and the other two exclusive
   access to one quarter each.

For more detailed information please refer to Intel SDM chapter
"Platform Shared Resource Control: Cache Allocation Technology".

In Xen's implementation, CBM can be configured with libxl/xl interfaces but
COS is maintained in hypervisor only. The cache partition granularity is per
domain, each domain has COS=0 assigned by default, the corresponding CBM is
all-ones, which means all the cache resource can be used by default.

### xl interfaces

System CAT information such as maximum COS and CBM length can be obtained by:

`xl psr-hwinfo --cat`

The simplest way to change a domain's CBM from its default is running:

`xl psr-cat-set  [OPTIONS] <domid> <cbm>`

where cbm is a number to represent the corresponding cache subset can be used.
A cbm is valid only when:

 * Set bits only exist in the range of [0, cbm_len), where cbm_len can be
   obtained with `xl psr-hwinfo --cat`.
 * All the set bits are contiguous.

In a multi-socket system, the same cbm will be set on each socket by default.
Per socket cbm can be specified with the `--socket SOCKET` option.

In different systems, the different cache level is supported, e.g. L3 cache or
L2 cache. Per cache level cbm can be specified with the `--level LEVEL` option.

Setting the CBM may not be successful if insufficient COS is available. In
such case unused COS(es) may be freed by setting CBM of all related domains to
its default value(all-ones).

Per domain CBM settings can be shown by:

`xl psr-cat-show [OPTIONS] <domid>`

In different systems, the different cache level is supported, e.g. L3 cache or
L2 cache. Per cache level cbm can be specified with the `--level LEVEL` option.

## Code and Data Prioritization (CDP)

Code and Data Prioritization (CDP) Technology is an extension of CAT, which
is available on Intel Broadwell and later server platforms. CDP enables
isolation and separate prioritization of code and data fetches to the L3
cache in a software configurable manner, which can enable workload
prioritization and tuning of cache capacity to the characteristics of the
workload. CDP extends Cache Allocation Technology (CAT) by providing
separate code and data masks per Class of Service (COS).

CDP can be enabled by adding `psr=cdp` to Xen command line.

When CDP is enabled,

 * the CAT masks are re-mapped into interleaved pairs of masks for data or
   code fetches.

 * the range of COS for CAT is re-indexed, with the lower-half of the COS
   range available for CDP.

CDP allows the OS or Hypervisor to partition cache allocation in a more
fine-grained manner. Code cache and data cache can be specified independently.
With CDP enabled, one COS corresponds to two CBMs (code CBM & data CBM),
since the sum of CBMs is fixed, that means the number of available COSes
will reduce by half when CDP is on.

For more detailed information please refer to Intel SDM chapter
"Platform Shared Resource Control: Cache Allocation Technology".

The xl interfaces are the same with that of CAT. The difference is that
CBM type can be passed as option to set code CBM or data CBM.

When CDP is enabled, `-c` or `--code` option is available to set code CBM
for the domain.

When CDP is enabled, `-d` or `--data` option is available to set data CBM
for the domain.

If neither `-c` nor `-d` option is specified when CDP is on, the same code
CBM and data CBM will be set for the domain. Passing both `-c` and `-d`
options is invalid.

Example:

Setting code CBM for a domain:
`xl psr-cat-set -c <domid> <cbm>`

Setting data CBM for a domain:
`xl psr-cat-set -d <domid> <cbm>`

Setting the same code and data CBM for a domain:
`xl psr-cat-set <domid> <cbm>`

## Memory Bandwidth Allocation (MBA)

Memory Bandwidth Allocation (MBA) is a new feature available on Intel
Skylake and later server platforms that allows an OS or Hypervisor/VMM to
slow misbehaving apps/VMs by using a credit-based throttling mechanism. To
enforce bandwidth on a specific domain, just set throttling value (THRTL)
into Class of Service (COS). MBA provides two THRTL mode. One is linear mode
and the other is non-linear mode.

In the linear mode the input precision is defined as 100-(THRTL_MAX). Values
not an even multiple of the precision (e.g., 12%) will be rounded down (e.g.,
to 10% delay by the hardware).

If linear values are not supported then input delay values are powers-of-two
from zero to the THRTL_MAX value from CPUID. In this case any values not a power
of two will be rounded down the next nearest power of two.

For example, assuming a system with 2 domains:

 * A THRTL of 0x0 for every domain means each domain can access the whole cache
   without any delay. This is the default.

 * Linear mode: Giving one domain a THRTL of 0xC and the other domain's 0 means
   that the first domain gets 10% delay to access the cache and the other one
   without any delay.

 * Non-linear mode: Giving one domain a THRTL of 0xC and the other domain's 0
   means that the first domain gets 8% delay to access the cache and the other
   one without any delay.

For more detailed information please refer to Intel SDM chapter
"Introduction to Memory Bandwidth Allocation".

In Xen's implementation, THRTL can be configured with libxl/xl interfaces but
COS is maintained in hypervisor only. The cache partition granularity is per
domain, each domain has COS=0 assigned by default, the corresponding THRTL is
0, which means all the cache resource can be accessed without delay.

### xl interfaces

System MBA information such as maximum COS and maximum THRTL can be obtained by:

`xl psr-hwinfo --mba`

The simplest way to change a domain's THRTL from its default is running:

`xl psr-mba-set  [OPTIONS] <domid> <thrtl>`

In a multi-socket system, the same thrtl will be set on each socket by default.
Per socket thrtl can be specified with the `--socket SOCKET` option.

Setting the THRTL may not be successful if insufficient COS is available. In
such case unused COS(es) may be freed by setting THRTL of all related domains to
its default value(0).

Per domain THRTL settings can be shown by:

`xl psr-mba-show [OPTIONS] <domid>`

For linear mode, it shows the decimal value. For non-linear mode, it shows
hexadecimal value.

## Reference

[1] Intel SDM
(http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html).
