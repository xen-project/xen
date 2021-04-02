***************************************************************************
Intel Cache Allocation Technology and Code and Data Prioritization Features
***************************************************************************

- Status: **Tech Preview**
- Architecture(s): Intel x86
- Component(s): Hypervisor, toolstack
- Hardware: L3 CAT: Haswell and beyond CPUs
            CDP   : Broadwell and beyond CPUs
            L2 CAT: Atom codename Goldmont and beyond CPUs

===========
Terminology
===========

* CAT         Cache Allocation Technology
* CBM         Capacity BitMasks
* CDP         Code and Data Prioritization
* CMT         Cache Monitoring Technology
* COS/CLOS    Class of Service
* MSRs        Machine Specific Registers
* PSR         Intel Platform Shared Resource

========
Overview
========

Intel provides a set of allocation capabilities including Cache Allocatation
Technology (CAT) and Code and Data Prioritization (CDP).

CAT allows an OS or hypervisor to control allocation of a CPU's shared cache
based on application/domain priority or Class of Service (COS). Each COS is
configured using capacity bitmasks (CBMs) which represent cache capacity and
indicate the degree of overlap and isolation between classes. Once CAT is
configured, the processor allows access to portions of cache according to the
established COS. Intel Xeon processor E5 v4 family (and some others) introduce
capabilities to configure and make use of the CAT mechanism on the L3 cache.
Intel Goldmont processor provides support for control over the L2 cache.

Code and Data Prioritization (CDP) Technology is an extension of CAT. CDP
enables isolation and separate prioritization of code and data fetches to
the L3 cache in a SW configurable manner, which can enable workload
prioritization and tuning of cache capacity to the characteristics of the
workload. CDP extends CAT by providing separate code and data masks per Class
of Service (COS). When SW configures to enable CDP, L3 CAT is disabled.

============
User Details
============

* Feature Enabling: Add "psr=cat" to boot line parameter to enable all supported level CAT features. Add "psr=cdp" to enable L3 CDP but disables L3 CAT by SW.

* xl Interfaces:

    1. `psr-cat-show [OPTIONS] domain-id`:

        Show L2 CAT or L3 CAT/CDP CBM of the domain designated by Xen domain-id.

        Option `-l`:

        `-l2`: Show cbm for L2 cache.

        `-l3`: Show cbm for L3 cache.

        If `-lX` is specified and LX is not supported, print error.
        If no `-l` is specified, level 3 is the default option.

    2. `psr-cat-set [OPTIONS] domain-id cbm`:

        Set L2 CAT or L3 CAT/CDP CBM to the domain designated by Xen domain-id.

        Option `-s`: Specify the socket to process, otherwise all sockets are
        processed.

        Option `-l`:

        `-l2`: Specify cbm for L2 cache.

        `-l3`: Specify cbm for L3 cache.

        If `-lX` is specified and LX is not supported, print error.
        If no `-l` is specified, level 3 is the default option.

        Option `-c` or `-d`:

        `-c`: Set L3 CDP code cbm.

        `-d`: Set L3 CDP data cbm.

    3. `psr-hwinfo [OPTIONS]`:

        Show CMT & L2 CAT & L3 CAT/CDP HW information on every socket.

        Option `-m, --cmt`: Show Cache Monitoring Technology (CMT) hardware
        info.

        Option `-a, --cat`: Show CAT/CDP hardware info.

=================
Technical Details
=================

L3 CAT/CDP and L2 CAT are all members of Intel PSR features, they share the base
PSR infrastructure in Xen.

Hardware Perspective
~~~~~~~~~~~~~~~~~~~~

CAT/CDP defines a range of MSRs to assign different cache access patterns
which are known as CBMs, each CBM is associated with a COS.

For example, L2 CAT:

                            +----------------------------+----------------+
       IA32_PQR_ASSOC       | MSR (per socket)           |    Address     |
     +----+---+-------+     +----------------------------+----------------+
     |    |COS|       |     | IA32_L2_QOS_MASK_0         |     0xD10      |
     +----+---+-------+     +----------------------------+----------------+
            +-------------> | ...                        |  ...           |
                            +----------------------------+----------------+
                            | IA32_L2_QOS_MASK_n         | 0xD10+n (n<64) |
                            +----------------------------+----------------+

L3 CAT/CDP uses a range of MSRs from 0xC90 ~ 0xC90+n (n<128).

L2 CAT uses a range of MSRs from 0xD10 ~ 0xD10+n (n<64), following the L3
CAT/CDP MSRs, setting different L2 cache accessing patterns from L3 cache is
supported.

Every MSR stores a CBM value. A capacity bitmask (CBM) provides a hint to the
hardware indicating the cache space a domain should be limited to as well as
providing an indication of overlap and isolation in the CAT-capable cache from
other domains contending for the cache.

Sample cache capacity bitmasks for a bitlength of 8 are shown below. Please
note that all (and only) contiguous '1' combinations are allowed (e.g. FFFFH,
0FF0H, 003CH, etc.).

           +----+----+----+----+----+----+----+----+
           | M7 | M6 | M5 | M4 | M3 | M2 | M1 | M0 |
           +----+----+----+----+----+----+----+----+
      COS0 | A  | A  | A  | A  | A  | A  | A  | A  | Default Bitmask
           +----+----+----+----+----+----+----+----+
      COS1 | A  | A  | A  | A  | A  | A  | A  | A  |
           +----+----+----+----+----+----+----+----+
      COS2 | A  | A  | A  | A  | A  | A  | A  | A  |
           +----+----+----+----+----+----+----+----+
    
           +----+----+----+----+----+----+----+----+
           | M7 | M6 | M5 | M4 | M3 | M2 | M1 | M0 |
           +----+----+----+----+----+----+----+----+
      COS0 | A  | A  | A  | A  | A  | A  | A  | A  | Overlapped Bitmask
           +----+----+----+----+----+----+----+----+
      COS1 |    |    |    |    | A  | A  | A  | A  |
           +----+----+----+----+----+----+----+----+
      COS2 |    |    |    |    |    |    | A  | A  |
           +----+----+----+----+----+----+----+----+
    
           +----+----+----+----+----+----+----+----+
           | M7 | M6 | M5 | M4 | M3 | M2 | M1 | M0 |
           +----+----+----+----+----+----+----+----+
      COS0 | A  | A  | A  | A  |    |    |    |    | Isolated Bitmask
           +----+----+----+----+----+----+----+----+
      COS1 |    |    |    |    | A  | A  |    |    |
           +----+----+----+----+----+----+----+----+
      COS2 |    |    |    |    |    |    | A  | A  |
           +----+----+----+----+----+----+----+----+

We can get the CBM length through CPUID. The default value of CBM is calculated
by `(1ull << cbm_len) - 1`. That is a fully open bitmask, all ones bitmask.
The COS\[0\] always stores the default value without change.

There is a `IA32_PQR_ASSOC` register which stores the COS ID of the VCPU. HW
enforces cache allocation according to the corresponding CBM.

Relationship between L3 CAT/CDP and L2 CAT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HW may support all features. By default, CDP is disabled on the processor.
If the L3 CAT MSRs are used without enabling CDP, the processor operates in
a traditional CAT-only mode. When CDP is enabled:

* the CAT mask MSRs are re-mapped into interleaved pairs of mask MSRs for
  data or code fetches.

* the range of COS for CAT is re-indexed, with the lower-half of the COS
  range available for CDP.

L2 CAT is independent of L3 CAT/CDP, which means L2 CAT can be enabled while
L3 CAT/CDP is disabled, or L2 CAT and L3 CAT/CDP are both enabled.

As a requirement, the bits of CBM of CAT/CDP must be continuous.

N.B. L2 CAT and L3 CAT/CDP share the same COS field in the same associate
register `IA32_PQR_ASSOC`, which means one COS is associated with a pair of
L2 CAT CBM and L3 CAT/CDP CBM.

Besides, the max COS of L2 CAT may be different from L3 CAT/CDP (or other
PSR features in future). In some cases, a domain is permitted to have a COS
that is beyond one (or more) of PSR features but within the others. For
instance, let's assume the max COS of L2 CAT is 8 but the max COS of L3
CAT is 16, when a domain is assigned 9 as COS, the L3 CAT CBM associated to
COS 9 would be enforced, but for L2 CAT, the HW works as default value is
set since COS 9 is beyond the max COS (8) of L2 CAT.

Design Overview
~~~~~~~~~~~~~~~

* Core COS/CBM association

    When enforcing CAT/CDP, all cores of domains have the same default COS
    (COS0) which is associated with the fully open CBM (all ones bitmask) to
    access all cache. The default COS is used only in hypervisor and is
    transparent to tool stack and user.

    System administrator can change PSR allocation policy at runtime by tool
    stack. Since L2 CAT shares COS with L3 CAT/CDP, a COS corresponds to a
    2-tuple, like \[L2 CBM, L3 CBM\] with only-CAT enabled, when CDP is
    enabled, one COS corresponds to a 3-tuple, like \[L2 CBM, L3 Code_CBM,
    L3 Data_CBM\]. If neither L3 CAT nor L3 CDP is enabled, things would be
    easier, one COS corresponds to one L2 CBM.

* VCPU schedule

    When context switch happens, the COS of VCPU is written to per-thread MSR
    `IA32_PQR_ASSOC`, and then hardware enforces cache allocation according to
    the corresponding CBM.

* Multi-sockets

    Different sockets may have different CAT/CDP capability (e.g. max COS)
    although it is consistent on the same socket. So the capability of
    per-socket CAT/CDP is specified.

    'psr-cat-set' can set CBM for one domain per socket. On each socket, we
    maintain a COS array for all domains. One domain uses one COS at one time.
    One COS stores the CBM of the domain to work. So, when a VCPU of the domain
    is migrated from socket 1 to socket 2, it follows configuration on socket 2.

    E.g. user sets domain 1 CBM on socket 1 to 0x7f which uses COS 9 but sets
    domain 1 CBM on socket 2 to 0x3f which uses COS 7. When VCPU of this domain
    is migrated from socket 1 to 2, the COS ID used is 7, that means 0x3f is the
    CBM to work for this domain 1 now.

Implementation Description
~~~~~~~~~~~~~~~~~~~~~~~~~~

* Hypervisor interfaces:

    1. Boot line parameter "psr=cat" enables L2 CAT and L3 CAT if hardware
       supported. "psr=cdp" enables CDP if hardware supported.

    2. SYSCTL:

        * XEN_SYSCTL_PSR_CAT_get_l3_info: Get L3 CAT/CDP information.
        * XEN_SYSCTL_PSR_CAT_get_l2_info: Get L2 CAT information.

    3. DOMCTL:

        * XEN_DOMCTL_PSR_CAT_OP_GET_L3_CBM: Get L3 CBM for a domain.
        * XEN_DOMCTL_PSR_CAT_OP_SET_L3_CBM: Set L3 CBM for a domain.
        * XEN_DOMCTL_PSR_CAT_OP_GET_L3_CODE: Get CDP Code CBM for a domain.
        * XEN_DOMCTL_PSR_CAT_OP_SET_L3_CODE: Set CDP Code CBM for a domain.
        * XEN_DOMCTL_PSR_CAT_OP_GET_L3_DATA: Get CDP Data CBM for a domain.
        * XEN_DOMCTL_PSR_CAT_OP_SET_L3_DATA: Set CDP Data CBM for a domain.
        * XEN_DOMCTL_PSR_CAT_OP_GET_L2_CBM: Get L2 CBM for a domain.
        * XEN_DOMCTL_PSR_CAT_OP_SET_L2_CBM: Set L2 CBM for a domain.

* xl interfaces:

    1. psr-cat-show -lX domain-id

        Show LX cbm for a domain.

                => XEN_SYSCTL_PSR_CAT_get_l3_info    /
                   XEN_SYSCTL_PSR_CAT_get_l2_info    /
                   XEN_DOMCTL_PSR_CAT_OP_GET_L3_CBM  /
                   XEN_DOMCTL_PSR_CAT_OP_GET_L3_CODE /
                   XEN_DOMCTL_PSR_CAT_OP_GET_L3_DATA /
                   XEN_DOMCTL_PSR_CAT_OP_GET_L2_CBM

    2. psr-cat-set -lX domain-id cbm

        Set LX cbm for a domain.

                => XEN_DOMCTL_PSR_CAT_OP_SET_L3_CBM  /
                   XEN_DOMCTL_PSR_CAT_OP_SET_L3_CODE /
                   XEN_DOMCTL_PSR_CAT_OP_SET_L3_DATA /
                   XEN_DOMCTL_PSR_CAT_OP_SET_L2_CBM

    3. psr-hwinfo

        Show PSR HW information, including L3 CAT/CDP/L2 CAT

                => XEN_SYSCTL_PSR_CAT_get_l3_info /
                   XEN_SYSCTL_PSR_CAT_get_l2_info

* Key data structure:

    1. Feature properties

            static const struct feat_props {
                unsigned int cos_num;
                enum cbm_type type[PSR_MAX_COS_NUM];
                enum cbm_type alt_type;
                bool (*get_feat_info)(const struct feat_node *feat,
                                      uint32_t data[], unsigned int array_len);
                void (*write_msr)(unsigned int cos, uint32_t val,
                                  enum cbm_type type);
            } *feat_props[PSR_SOCKET_FEAT_NUM];

        Every feature has its own properties, e.g. some data and actions. A
        feature property pointer array is declared to save every feature's
        properties.

        * Member `cos_num`

            `cos_num` is the number of COS registers the feature uses, e.g.
            L3/L2 CAT uses 1 register but CDP uses 2 registers.

        * Member `type`

            `type` is an array to save all 'enum cbm_type' values of the
            feature. It is used with cos_num together to get/write a feature's
            COS registers values one by one.

        * Member `alt_type`

            `alt_type` is 'alternative type'. When this 'alt_type' is input,
            the feature does some special operations.

        * Member `get_feat_info`

            `get_feat_info` is used to return feature HW info through sysctl.

        * Member `write_msr`

            `write_msr` is used to write out feature MSR register.

    2. Feature node

            struct feat_node {
                unsigned int cos_max;
                unsigned int cbm_len;
                uint32_t cos_reg_val[MAX_COS_REG_CNT];
            };

        When a PSR enforcement feature is enabled, it will be added into a
        feature array.

        * Member `cos_max`

            `cos_max` is one of the hardware info of CAT. It means the max
            number of COS registers. As L3 CAT/CDP/L2 CAT all have it, it is
            declared in `feat_node`.

        * Member `cbm_len`

            `cbm_len` is one of the hardware info of CAT. It means the max
            number of bits to set.

        * Member `cos_reg_val`

            `cos_reg_val` is an array to maintain the value set in all COS
            registers of the feature. The array is indexed by COS ID.

    3. Per-socket PSR features information structure

            struct psr_socket_info {
                bool feat_init;
                struct feat_node *features[PSR_SOCKET_FEAT_NUM];
                spinlock_t ref_lock;
                unsigned int cos_ref[MAX_COS_REG_CNT];
                DECLARE_BITMAP(dom_ids, DOMID_IDLE + 1);
            };

        We collect all PSR allocation features information of a socket in this
        `struct psr_socket_info`.

        * Member `feat_init`

            `feat_init` is a flag, to indicate whether the CPU init on a socket
            has been done.

        * Member `features`

            `features` is a pointer array to save all enabled features pointers
            according to feature position defined in `enum psr_feat_type`.

        * Member `ref_lock`

            `ref_lock` is a spin lock to protect `cos_ref`.

        * Member `cos_ref`

            `cos_ref` is an array which maintains the reference of one COS.
            It maps to cos_reg_val\[MAX_COS_REG_NUM\] in `struct feat_node`.
            If one COS is used by one domain, the corresponding reference will
            increase by one. If a domain releases the COS, the reference will
            decrease by one. The array is indexed by COS ID.

        * Member `dom_ids`

            `dom_ids` is a bitmap, every bit corresponds to a domain. Index is
            domain_id. It is used to help restore the cos_id of the domain to 0
            when a socket is offline and then online again.

===========
Limitations
===========

CAT/CDP can only work on HW which enables it(check by CPUID). So far, there is
no HW which enables both L2 CAT and L3 CAT/CDP. But SW implementation has
considered such scenario to enable both L2 CAT and L3 CAT/CDP.

=======
Testing
=======

We can execute above xl commands to verify L2 CAT and L3 CAT/CDP on different
HWs support them.

For example:

    root@:~$ xl psr-hwinfo --cat
    Cache Allocation Technology (CAT): L2
    Socket ID       : 0
    Maximum COS     : 3
    CBM length      : 8
    Default CBM     : 0xff

    root@:~$ xl psr-cat-cbm-set -l2 1 0x7f

    root@:~$ xl psr-cat-show -l2 1
    Socket ID       : 0
    Default CBM     : 0xff
       ID                     NAME             CBM
        1                 ubuntu14            0x7f

=====================
Areas for Improvement
=====================

A hexadecimal number is used to set/show CBM for a domain now. Although this
is convenient to cover overlap/isolated bitmask requirement, it is not
user-friendly.

To improve this, the libxl interfaces can be wrapped in libvirt to provide more
user-friendly interfaces to user, e.g. a percentage number of the cache to set
and show.

============
Known Issues
============

N/A

==========
References
==========

`INTEL RESOURCE DIRECTOR TECHNOLOGY (INTEL RDT) ALLOCATION FEATURES [Intel 64 and IA-32 Architectures Software Developer Manuals, vol3 <http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html>`__

=========
Changelog
=========

+--------+-------+-------+--------------------------------------+
| Date   | Rev   | Ve    | Notes                                |
|        | ision | rsion |                                      |
+========+=======+=======+======================================+
| 2016   | 1.0   | Xen   | Design document written              |
| -08-12 |       | 4.9   |                                      |
+--------+-------+-------+--------------------------------------+
| 2017   | 1.7   | Xen   | Changes:                             |
| -02-13 |       | 4.9   |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Modify the design document to     |
|        |       |       | cover L3 CAT/CDP and L2 CAT;         |
+--------+-------+-------+--------------------------------------+
|        |       |       | 2. Fix typos;                        |
+--------+-------+-------+--------------------------------------+
|        |       |       | 3. Amend description of              |
|        |       |       | ``feat_mask`` to make it clearer;    |
+--------+-------+-------+--------------------------------------+
|        |       |       | 4. Other minor changes.              |
+--------+-------+-------+--------------------------------------+
| 2017   | 1.8   | Xen   | Changes:                             |
| -02-15 |       | 4.9   |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Add content in ‘Areas for         |
|        |       |       | improvement’;                        |
+--------+-------+-------+--------------------------------------+
|        |       |       | 2. Adjust revision number.           |
+--------+-------+-------+--------------------------------------+
| 2017   | 1.9   | Xen   | Changes:                             |
| -03-16 |       | 4.9   |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Add ‘CMT’ in ‘Terminology’;       |
+--------+-------+-------+--------------------------------------+
|        |       |       | 2. Change ‘feature list’ to ‘feature |
|        |       |       | array’.                              |
+--------+-------+-------+--------------------------------------+
|        |       |       | 3. Modify data structure             |
|        |       |       | descriptions.                        |
+--------+-------+-------+--------------------------------------+
|        |       |       | 4. Adjust revision number.           |
+--------+-------+-------+--------------------------------------+
| 2017   | 1.11  | Xen   | Changes:                             |
| -05-03 |       | 4.9   |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Modify data structure             |
|        |       |       | descriptions.                        |
+--------+-------+-------+--------------------------------------+
|        |       |       | 2. Adjust revision number.           |
+--------+-------+-------+--------------------------------------+
| 2017   | 1.14  | Xen   | Changes:                             |
| -07-13 |       | 4.10  |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Fix a typo.                       |
+--------+-------+-------+--------------------------------------+
| 2017   | 1.15  | Xen   | Changes:                             |
| -08-01 |       | 4.10  |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Add ‘alt_type’ in ‘feat_props’    |
|        |       |       | structure.                           |
+--------+-------+-------+--------------------------------------+
| 2017   | 1.16  | Xen   | Changes:                             |
| -08-04 |       | 4.10  |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Remove special character which    |
|        |       |       | may cause html creation failure.     |
+--------+-------+-------+--------------------------------------+
| 2018   | 1.17  | Xen   | Changes:                             |
| -07-10 |       | 4.12  |                                      |
+--------+-------+-------+--------------------------------------+
|        |       |       | 1. Reformat complete document to     |
|        |       |       | enable PDF creation.                 |
+--------+-------+-------+--------------------------------------+
