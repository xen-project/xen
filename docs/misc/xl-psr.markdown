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
partition cache allocation (i.e. L3 cache) based on application priority or
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

`xl psr-cat-cbm-set  [OPTIONS] <domid> <cbm>`

where cbm is a number to represent the corresponding cache subset can be used.
A cbm is valid only when:

 * Set bits only exist in the range of [0, cbm_len), where cbm_len can be
   obtained with `xl psr-hwinfo --cat`.
 * All the set bits are contiguous.

In a multi-socket system, the same cbm will be set on each socket by default.
Per socket cbm can be specified with the `--socket SOCKET` option.

Setting the CBM may not be successful if insufficient COS is available. In
such case unused COS(es) may be freed by setting CBM of all related domains to
its default value(all-ones).

Per domain CBM settings can be shown by:

`xl psr-cat-show`

## Reference

[1] Intel SDM
(http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html).
