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

The Xen hypervisor deals with NUMA machines by assigning to each domain
a "node affinity", i.e., a set of NUMA nodes of the host from which they
get their memory allocated. Also, even if the node affinity of a domain
is allowed to change on-line, it is very important to "place" the domain
correctly when it is fist created, as the most of its memory is allocated
at that time and can not (for now) be moved easily.

NUMA awareness becomes very important as soon as many domains start
running memory-intensive workloads on a shared host. In fact, the cost
of accessing non node-local memory locations is very high, and the
performance degradation is likely to be noticeable.

For more information, have a look at the [Xen NUMA Introduction][numa_intro]
page on the Wiki.

### Placing via pinning and cpupools ###

The simplest way of placing a domain on a NUMA node is statically pinning
the domain's vCPUs to the pCPUs of the node. This goes under the name of
CPU affinity and can be set through the "cpus=" option in the config file
(more about this below). Another option is to pool together the pCPUs
spanning the node and put the domain in such a cpupool with the "pool="
config option (as documented in our [Wiki][cpupools_howto]).

In both the above cases, the domain will not be able to execute outside
the specified set of pCPUs for any reasons, even if all those pCPUs are
busy doing something else while there are others, idle, pCPUs.

So, when doing this, local memory accesses are 100% guaranteed, but that
may come at he cost of some load imbalances.

### NUMA aware scheduling ###

If the credit scheduler is in use, the concept of node affinity defined
above does not only apply to memory. In fact, starting from Xen 4.3, the
scheduler always tries to run the domain's vCPUs on one of the nodes in
its node affinity. Only if that turns out to be impossible, it will just
pick any free pCPU.

This is, therefore, something more flexible than CPU affinity, as a domain
can still run everywhere, it just prefers some nodes rather than others.
Locality of access is less guaranteed than in the pinning case, but that
comes along with better chances to exploit all the host resources (e.g.,
the pCPUs).

In fact, if all the pCPUs in a domain's node affinity are busy, it is
possible for the domain to run outside of there, but it is very likely that
slower execution (due to remote memory accesses) is still better than no
execution at all, as it would happen with pinning. For this reason, NUMA
aware scheduling has the potential of bringing substantial performances
benefits, although this will depend on the workload.

## Guest placement in xl ##

If using xl for creating and managing guests, it is very easy to ask for
both manual or automatic placement of them across the host's NUMA nodes.

Note that xm/xend does a very similar thing, the only differences being
the details of the heuristics adopted for automatic placement (see below),
and the lack of support (in both xm/xend and the Xen versions where that\
was the default toolstack) for NUMA aware scheduling.

### Placing the guest manually ###

Thanks to the "cpus=" option, it is possible to specify where a domain
should be created and scheduled on, directly in its config file. This
affects NUMA placement and memory accesses as the hypervisor constructs
the node affinity of a VM basing right on its CPU affinity when it is
created.

This is very simple and effective, but requires the user/system
administrator to explicitly specify affinities for each and every domain,
or Xen won't be able to guarantee the locality for their memory accesses.

Notice that this also pins the domain's vCPUs to the specified set of
pCPUs, so it not only sets the domain's node affinity (its memory will
come from the nodes to which the pCPUs belong), but at the same time
forces the vCPUs of the domain to be scheduled on those same pCPUs.

### Placing the guest automatically ###

If no "cpus=" option is specified in the config file, libxl tries
to figure out on its own on which node(s) the domain could fit best.
If it finds one (some), the domain's node affinity get set to there,
and both memory allocations and NUMA aware scheduling (for the credit
scheduler and starting from Xen 4.3) will comply with it.

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

Also, if `numa_placement` is set to `true`, the domain must not
have any CPU affinity (i.e., `domain_build_info->cpumap` must
have all its bits set, as it is by default), or domain creation
will fail returning `ERROR_INVAL`.

Starting from Xen 4.3, in case automatic placement happens (and is
successful), it will affect the domain's node affinity and _not_ its
CPU affinity. Namely, the domain's vCPUs will not be pinned to any
pCPU on the host, but the memory from the domain will come from the
selected node(s) and the NUMA aware scheduling (if the credit scheduler
is in use) will try to keep the domain there as much as possible.

Besides than that, looking and/or tweaking the placement algorithm
search "Automatic NUMA placement" in libxl\_internal.h.

Note this may change in future versions of Xen/libxl.

## Xen < 4.3 ##

As NUMA aware scheduling is a new feature of Xen 4.3, things are a little
bit different for earlier version of Xen. If no "cpus=" option is specified
and Xen 4.2 is in use, the automatic placement algorithm still runs, but
the results is used to _pin_ the vCPUs of the domain to the output node(s).
This is consistent with what was happening with xm/xend, which were also
affecting the domain's CPU affinity.

On a version of Xen earlier than 4.2, there is not automatic placement at
all in xl or libxl, and hence no node or CPU affinity being affected.

## Limitations ##

Analyzing various possible placement solutions is what makes the
algorithm flexible and quite effective. However, that also means
it won't scale well to systems with arbitrary number of nodes.
For this reason, automatic placement is disabled (with a warning)
if it is requested on a host with more than 16 NUMA nodes.

[numa_intro]: http://wiki.xen.org/wiki/Xen_NUMA_Introduction
[cpupools_howto]: http://wiki.xen.org/wiki/Cpupools_Howto
