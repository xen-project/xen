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

If needed, change the buddy allocator reserved size with
``CONFIG_BUDDY_ALLOCATOR_SIZE=<n>``.

Runtime configuration is done via `Command line parameters`_.
For DomUs follow `DomUs configuration`_.

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
| ``buddy-alloc-size`` | Buddy allocator reserved size |
+----------------------+-------------------------------+
| ``xen-llc-colors``   | Xen color configuration       |
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

DomUs configuration
*******************

DomUs colors can be set either in the ``xl`` configuration file (documentation
at `docs/man/xl.cfg.pod.5.in`) or via Device Tree (documentation at
`docs/misc/arm/device-tree/booting.txt`) using the ``llc-colors`` option.
For example:

::

    xen,xen-bootargs = "console=dtuart dtuart=serial0 dom0_mem=1G dom0_max_vcpus=1 sched=null llc-coloring=on dom0-llc-colors=2-6";
    xen,dom0-bootargs "console=hvc0 earlycon=xen earlyprintk=xen root=/dev/ram0"

    dom0 {
        compatible = "xen,linux-zimage" "xen,multiboot-module";
        reg = <0x0 0x1000000 0x0 15858176>;
    };

    dom0-ramdisk {
        compatible = "xen,linux-initrd" "xen,multiboot-module";
        reg = <0x0 0x2000000 0x0 20638062>;
    };

    domU0 {
        #address-cells = <0x1>;
        #size-cells = <0x1>;
        compatible = "xen,domain";
        memory = <0x0 0x40000>;
        llc-colors = "4-8,10,11,12";
        cpus = <0x1>;
        vpl011 = <0x1>;

        module@2000000 {
            compatible = "multiboot,kernel", "multiboot,module";
            reg = <0x2000000 0xffffff>;
            bootargs = "console=ttyAMA0";
        };

        module@30000000 {
            compatible = "multiboot,ramdisk", "multiboot,module";
            reg = <0x3000000 0xffffff>;
        };
    };

**Note:** If no color configuration is provided for a domain, the default one,
which corresponds to all available colors is used instead.

Colored allocator and buddy allocator
*************************************

The colored allocator distributes pages based on color configurations of
domains so that each domains only gets pages of its own colors.
The colored allocator is meant as an alternative to the buddy allocator because
its allocation policy is by definition incompatible with the generic one. Since
the Xen heap is not colored yet, we need to support the coexistence of the two
allocators and some memory must be left for the buddy one. Buddy memory
reservation is configured via Kconfig or via command-line.

Known issues and limitations
****************************

"xen,static-mem" isn't supported when coloring is enabled
#########################################################

In the domain configuration, "xen,static-mem" allows memory to be statically
allocated to the domain. This isn't possible when LLC coloring is enabled,
because that memory can't be guaranteed to use only colors assigned to the
domain.

Cache coloring is intended only for embedded systems
####################################################

The current implementation aims to satisfy the need of predictability in
embedded systems with small amount of memory to be managed in a colored way.
Given that, some shortcuts are taken in the development. Expect worse
performances on larger systems.

Colored allocator can only make use of order-0 pages
####################################################

The cache coloring technique relies on memory mappings and on the smallest
mapping granularity to achieve the maximum number of colors (cache partitions)
possible. This granularity is what is normally called a page and, in Xen
terminology, the order-0 page is the smallest one. The fairly simple
colored allocator currently implemented, makes use only of such pages.
It must be said that a more complex one could, in theory, adopt higher order
pages if the colors selection contained adjacent colors. Two subsequent colors,
for example, can be represented by an order-1 page, four colors correspond to
an order-2 page, etc.
