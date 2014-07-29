# Guest Automatic NUMA Placement in libxl and xl #

## Rationale ##

NUMA (which stands for Non-Uniform Memory Access) means that the memory
accessing times of a program running on a CPU depends on the relative
distance between that CPU and that memory. In fact, most of the NUMA
systems are built in such a way that each processor has its local memory,
on which it can operate very fast. On the other hand, getting and storing
data from and on remote memory (that is, memory local to some other processor)
is quite more complex and slow. On these machines, a NUMA node is usually
defined as a set of processor cores (typically a physical CPU package) and
the memory directly attached to the set of cores.

NUMA awareness becomes very important as soon as many domains start
running memory-intensive workloads on a shared host. In fact, the cost
of accessing non node-local memory locations is very high, and the
performance degradation is likely to be noticeable.

For more information, have a look at the [Xen NUMA Introduction][numa_intro]
page on the Wiki.

## Xen and NUMA machines: the concept of _node-affinity_ ##

The Xen hypervisor deals with NUMA machines throughout the concept of
_node-affinity_. The node-affinity of a domain is the set of NUMA nodes
of the host where the memory for the domain is being allocated (mostly,
at domain creation time). This is, at least in principle, different and
unrelated with the vCPU (hard and soft, see below) scheduling affinity,
which instead is the set of pCPUs where the vCPU is allowed (or prefers)
to run.

Of course, despite the fact that they belong to and affect different
subsystems, the domain node-affinity and the vCPUs affinity are not
completely independent.
In fact, if the domain node-affinity is not explicitly specified by the
user, via the proper libxl calls or xl config item, it will be computed
basing on the vCPUs' scheduling affinity.

Notice that, even if the node affinity of a domain may change on-line,
it is very important to "place" the domain correctly when it is fist
created, as the most of its memory is allocated at that time and can
not (for now) be moved easily.

### Placing via pinning and cpupools ###

The simplest way of placing a domain on a NUMA node is setting the hard
scheduling affinity of the domain's vCPUs to the pCPUs of the node. This
also goes under the name of vCPU pinning, and can be done through the
"cpus=" option in the config file (more about this below). Another option
is to pool together the pCPUs spanning the node and put the domain in
such a _cpupool_ with the "pool=" config option (as documented in our
[Wiki][cpupools_howto]).

In both the above cases, the domain will not be able to execute outside
the specified set of pCPUs for any reasons, even if all those pCPUs are
busy doing something else while there are others, idle, pCPUs.

So, when doing this, local memory accesses are 100% guaranteed, but that
may come at he cost of some load imbalances.

### NUMA aware scheduling ###

If using the credit1 scheduler, and starting from Xen 4.3, the scheduler
itself always tries to run the domain's vCPUs on one of the nodes in
its node-affinity. Only if that turns out to be impossible, it will just
pick any free pCPU. Locality of access is less guaranteed than in the
pinning case, but that comes along with better chances to exploit all
the host resources (e.g., the pCPUs).

Starting from Xen 4.5, credit1 supports two forms of affinity: hard and
soft, both on a per-vCPU basis. This means each vCPU can have its own
soft affinity, stating where such vCPU prefers to execute on. This is
less strict than what it (also starting from 4.5) is called hard affinity,
as the vCPU can potentially run everywhere, it just prefers some pCPUs
rather than others.
In Xen 4.5, therefore, NUMA-aware scheduling is achieved by matching the
soft affinity of the vCPUs of a domain with its node-affinity.

In fact, as it was for 4.3, if all the pCPUs in a vCPU's soft affinity
are busy, it is possible for the domain to run outside from there. The
idea is that slower execution (due to remote memory accesses) is still
better than no execution at all (as it would happen with pinning). For
this reason, NUMA aware scheduling has the potential of bringing
substantial performances benefits, although this will depend on the
workload.

Notice that, for each vCPU, the following three scenarios are possbile:

  * a vCPU *is pinned* to some pCPUs and *does not have* any soft affinity
    In this case, the vCPU is always scheduled on one of the pCPUs to which
    it is pinned, without any specific peference among them.
  * a vCPU *has* its own soft affinity and *is not* pinned to any particular
    pCPU. In this case, the vCPU can run on every pCPU. Nevertheless, the
    scheduler will try to have it running on one of the pCPUs in its soft
    affinity;
  * a vCPU *has* its own vCPU soft affinity and *is also* pinned to some
    pCPUs. In this case, the vCPU is always scheduled on one of the pCPUs
    onto which it is pinned, with, among them, a preference for the ones
    that also forms its soft affinity. In case pinning and soft affinity
    form two disjoint sets of pCPUs, pinning "wins", and the soft affinity
    is just ignored.

## Guest placement in xl ##

If using xl for creating and managing guests, it is very easy to ask for
both manual or automatic placement of them across the host's NUMA nodes.

Note that xm/xend does a very similar thing, the only differences being
the details of the heuristics adopted for automatic placement (see below),
and the lack of support (in both xm/xend and the Xen versions where that
was the default toolstack) for NUMA aware scheduling.

### Placing the guest manually ###

Thanks to the "cpus=" option, it is possible to specify where a domain
should be created and scheduled on, directly in its config file. This
affects NUMA placement and memory accesses as, in this case, the
hypervisor constructs the node-affinity of a VM basing right on its
vCPU pinning when it is created.

This is very simple and effective, but requires the user/system
administrator to explicitly specify the pinning for each and every domain,
or Xen won't be able to guarantee the locality for their memory accesses.

That, of course, also mean the vCPUs of the domain will only be able to
execute on those same pCPUs.

It is is also possible to have a "cpus\_soft=" option in the xl config file,
to specify the soft affinity for all the vCPUs of the domain. This affects
the NUMA placement in the following way:

 * if only "cpus\_soft=" is present, the VM's node-affinity will be equal
   to the nodes to which the pCPUs in the soft affinity mask belong;
 * if both "cpus\_soft=" and "cpus=" are present, the VM's node-affinity
   will be equal to the nodes to which the pCPUs present both in hard and
   soft affinity belong.

### Placing the guest automatically ###

If neither "cpus=" nor "cpus\_soft=" are present in the config file, libxl
tries to figure out on its own on which node(s) the domain could fit best.
If it finds one (some), the domain's node affinity get set to there,
and both memory allocations and NUMA aware scheduling (for the credit
scheduler and starting from Xen 4.3) will comply with it. Starting from
Xen 4.5, this also means that the mask resulting from this "fitting"
procedure will become the soft affinity of all the vCPUs of the domain.

It is worthwhile noting that optimally fitting a set of VMs on the NUMA
nodes of an host is an incarnation of the Bin Packing Problem. In fact,
the various VMs with different memory sizes are the items to be packed,
and the host nodes are the bins. As such problem is known to be NP-hard,
we will be using some heuristics.

The first thing to do is find the nodes or the sets of nodes (from now
on referred to as 'candidates') that have enough free memory and enough
physical CPUs for accommodating the new domain. The idea is to find a
spot for the domain with at least as much free memory as it has configured
to have, and as much pCPUs as it has vCPUs.  After that, the actual
decision on which candidate to pick happens accordingly to the following
heuristics:

  *  candidates involving fewer nodes are considered better. In case
     two (or more) candidates span the same number of nodes,
  *  candidates with a smaller number of vCPUs runnable on them (due
     to previous placement and/or plain vCPU pinning) are considered
     better. In case the same number of vCPUs can run on two (or more)
     candidates,
  *  the candidate with with the greatest amount of free memory is
     considered to be the best one.

Giving preference to candidates with fewer nodes ensures better
performance for the guest, as it avoid spreading its memory among
different nodes. Favoring candidates with fewer vCPUs already runnable
there ensures a good balance of the overall host load. Finally, if more
candidates fulfil these criteria, prioritizing the nodes that have the
largest amounts of free memory helps keeping the memory fragmentation
small, and maximizes the probability of being able to put more domains
there.

## Guest placement in libxl ##

xl achieves automatic NUMA placement because that is what libxl does
by default. No API is provided (yet) for modifying the behaviour of
the placement algorithm. However, if your program is calling libxl,
it is possible to set the `numa_placement` build info key to `false`
(it is `true` by default) with something like the below, to prevent
any placement from happening:

    libxl_defbool_set(&domain_build_info->numa_placement, false);

Also, if `numa_placement` is set to `true`, the domain's vCPUs must
not be pinned (i.e., `domain_build_info->cpumap` must have all its
bits set, as it is by default), or domain creation will fail with
`ERROR_INVAL`.

Starting from Xen 4.3, in case automatic placement happens (and is
successful), it will affect the domain's node-affinity and _not_ its
vCPU pinning. Namely, the domain's vCPUs will not be pinned to any
pCPU on the host, but the memory from the domain will come from the
selected node(s) and the NUMA aware scheduling (if the credit scheduler
is in use) will try to keep the domain's vCPUs there as much as possible.

Besides than that, looking and/or tweaking the placement algorithm
search "Automatic NUMA placement" in libxl\_internal.h.

Note this may change in future versions of Xen/libxl.

## Xen < 4.5 ##

The concept of vCPU soft affinity has been introduced for the first time
in Xen 4.5. In 4.3, it is the domain's node-affinity that drives the
NUMA-aware scheduler. The main difference is soft affinity is per-vCPU,
and so each vCPU can have its own mask of pCPUs, while node-affinity is
per-domain, that is the equivalent of having all the vCPUs with the same
soft affinity.

## Xen < 4.3 ##

As NUMA aware scheduling is a new feature of Xen 4.3, things are a little
bit different for earlier version of Xen. If no "cpus=" option is specified
and Xen 4.2 is in use, the automatic placement algorithm still runs, but
the results is used to _pin_ the vCPUs of the domain to the output node(s).
This is consistent with what was happening with xm/xend.

On a version of Xen earlier than 4.2, there is not automatic placement at
all in xl or libxl, and hence no node-affinity, vCPU affinity or pinning
being introduced/modified.

## Limitations ##

Analyzing various possible placement solutions is what makes the
algorithm flexible and quite effective. However, that also means
it won't scale well to systems with arbitrary number of nodes.
For this reason, automatic placement is disabled (with a warning)
if it is requested on a host with more than 16 NUMA nodes.

[numa_intro]: http://wiki.xen.org/wiki/Xen_NUMA_Introduction
[cpupools_howto]: http://wiki.xen.org/wiki/Cpupools_Howto
