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
get their memory allocated.

NUMA awareness becomes very important as soon as many domains start
running memory-intensive workloads on a shared host. In fact, the cost
of accessing non node-local memory locations is very high, and the
performance degradation is likely to be noticeable.

## Guest Placement in xl ##

If using xl for creating and managing guests, it is very easy to ask for
both manual or automatic placement of them across the host's NUMA nodes.

Note that xm/xend does the very same thing, the only differences residing
in the details of the heuristics adopted for the placement (see below).

### Manual Guest Placement with xl ###

Thanks to the "cpus=" option, it is possible to specify where a domain
should be created and scheduled on, directly in its config file. This
affects NUMA placement and memory accesses as the hypervisor constructs
the node affinity of a VM basing right on its CPU affinity when it is
created.

This is very simple and effective, but requires the user/system
administrator to explicitly specify affinities for each and every domain,
or Xen won't be able to guarantee the locality for their memory accesses.

It is also possible to deal with NUMA by partitioning the system using
cpupools. Again, this could be "The Right Answer" for many needs and
occasions, but has to be carefully considered and setup by hand.

### Automatic Guest Placement with xl ###

If no "cpus=" option is specified in the config file, libxl tries
to figure out on its own on which node(s) the domain could fit best.
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

## Guest Placement within libxl ##

xl achieves automatic NUMA placement because that is what libxl does
by default. No API is provided (yet) for modifying the behaviour of
the placement algorithm. However, if your program is calling libxl,
it is possible to set the `numa_placement` build info key to `false`
(it is `true` by default) with something like the below, to prevent
any placement from happening:

    libxl_defbool_set(&domain_build_info->numa_placement, false);

Also, if `numa_placement` is set to `true`, the domain must not
have any cpu affinity (i.e., `domain_build_info->cpumap` must
have all its bits set, as it is by default), or domain creation
will fail returning `ERROR_INVAL`.

Besides than that, looking and/or tweaking the placement algorithm
search "Automatic NUMA placement" in libxl\_internal.h.

Note this may change in future versions of Xen/libxl.

## Limitations ##

Analyzing various possible placement solutions is what makes the
algorithm flexible and quite effective. However, that also means
it won't scale well to systems with arbitrary number of nodes.
For this reason, automatic placement is disabled (with a warning)
if it is requested on a host with more than 16 NUMA nodes.
