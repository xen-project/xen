.. SPDX-License-Identifier: CC-BY-4.0

Xen cache coloring user guide
=============================

The cache coloring support in Xen allows to reserve Last Level Cache (LLC)
partitions for Dom0, DomUs and Xen itself. Currently only ARM64 is supported.
Cache coloring realizes per-set cache partitioning in software and is applicable
to shared LLCs as implemented in Cortex-A53, Cortex-A72 and similar CPUs.

To compile LLC coloring support set ``CONFIG_LLC_COLORING=y``.

If needed, change the maximum number of colors with
``CONFIG_LLC_COLORS_ORDER=<n>``.

Runtime configuration is done via `Command line parameters`_.

Background
**********

Cache hierarchy of a modern multi-core CPU typically has first levels dedicated
to each core (hence using multiple cache units), while the last level is shared
among all of them. Such configuration implies that memory operations on one
core (e.g. running a DomU) are able to generate interference on another core
(e.g. hosting another DomU). Cache coloring realizes per-set cache-partitioning
in software and mitigates this, guaranteeing more predictable performances for
memory accesses.
Software-based cache coloring is particularly useful in those situations where
no hardware mechanisms (e.g., DSU-based way partitioning) are available to
partition caches. This is the case for e.g., Cortex-A53, A57 and A72 CPUs that
feature a L2 LLC cache shared among all cores.

The key concept underlying cache coloring is a fragmentation of the memory
space into a set of sub-spaces called colors that are mapped to disjoint cache
partitions. Technically, the whole memory space is first divided into a number
of subsequent regions. Then each region is in turn divided into a number of
subsequent sub-colors. The generic i-th color is then obtained by all the
i-th sub-colors in each region.

::

                            Region j            Region j+1
                .....................   ............
                .                     . .
                .                       .
            _ _ _______________ _ _____________________ _ _
                |     |     |     |     |     |     |
                | c_0 | c_1 |     | c_n | c_0 | c_1 |
           _ _ _|_____|_____|_ _ _|_____|_____|_____|_ _ _
                    :                       :
                    :                       :...         ... .
                    :                            color 0
                    :...........................         ... .
                                                :
          . . ..................................:

How colors are actually defined depends on the function that maps memory to
cache lines. In case of physically-indexed, physically-tagged caches with linear
mapping, the set index is found by extracting some contiguous bits from the
physical address. This allows colors to be defined as shown in figure: they
appear in memory as subsequent blocks of equal size and repeats themselves after
``n`` different colors, where ``n`` is the total number of colors.

If some kind of bit shuffling appears in the mapping function, then colors
assume a different layout in memory. Those kind of caches aren't supported by
the current implementation.

**Note**: Finding the exact cache mapping function can be a really difficult
task since it's not always documented in the CPU manual. As said Cortex-A53, A57
and A72 are known to work with the current implementation.

How to compute the number of colors
###################################

Given the linear mapping from physical memory to cache lines for granted, the
number of available colors for a specific platform is computed using three
parameters:

- the size of the LLC.
- the number of the LLC ways.
- the page size used by Xen.

The first two parameters can be found in the processor manual, while the third
one is the minimum mapping granularity. Dividing the cache size by the number of
its ways we obtain the size of a way. Dividing this number by the page size,
the number of total cache colors is found. So for example an Arm Cortex-A53
with a 16-ways associative 1 MiB LLC can isolate up to 16 colors when pages are
4 KiB in size.

Effective colors assignment
###########################

When assigning colors, if one wants to avoid cache interference between two
domains, different colors needs to be used for their memory.

Command line parameters
***********************

Specific documentation is available at `docs/misc/xen-command-line.pandoc`.

+----------------------+-------------------------------+
| **Parameter**        | **Description**               |
+----------------------+-------------------------------+
| ``llc-coloring``     | Enable coloring at runtime    |
+----------------------+-------------------------------+
| ``llc-size``         | Set the LLC size              |
+----------------------+-------------------------------+
| ``llc-nr-ways``      | Set the LLC number of ways    |
+----------------------+-------------------------------+
| ``dom0-llc-colors``  | Dom0 color configuration      |
+----------------------+-------------------------------+

Colors selection format
***********************

Regardless of the memory pool that has to be colored (Xen, Dom0/DomUs),
the color selection can be expressed using the same syntax. In particular a
comma-separated list of colors or ranges of colors is used.
Ranges are hyphen-separated intervals (such as `0-4`) and are inclusive on both
sides.

Note that:

- no spaces are allowed between values.
- no overlapping ranges or duplicated colors are allowed.
- values must be written in ascending order.

Examples:

+-------------------+-----------------------------+
| **Configuration** | **Actual selection**        |
+-------------------+-----------------------------+
| 1-2,5-8           | [1, 2, 5, 6, 7, 8]          |
+-------------------+-----------------------------+
| 4-8,10,11,12      | [4, 5, 6, 7, 8, 10, 11, 12] |
+-------------------+-----------------------------+
| 0                 | [0]                         |
+-------------------+-----------------------------+

Auto-probing of LLC specs
#########################

LLC size and number of ways are probed automatically by default.

In the Arm implementation, this is done by inspecting the CLIDR_EL1 register.
This means that other system caches that aren't visible there are ignored.

LLC specs can be manually set via the above command line parameters. This
bypasses any auto-probing and it's used to overcome failing situations, such as
flawed probing logic, or for debugging/testing purposes.

Known issues and limitations
****************************

"xen,static-mem" isn't supported when coloring is enabled
#########################################################

In the domain configuration, "xen,static-mem" allows memory to be statically
allocated to the domain. This isn't possible when LLC coloring is enabled,
because that memory can't be guaranteed to use only colors assigned to the
domain.
