*****************
Feature Levelling
*****************

- Status: **Supported**
- Architecture: x86
- Components: Hypervisor, toolstack, guest

========
Overview
========

On native hardware, a kernel boots, detects features, and typically optimizes certain codepaths based on the available features, and expect the features to remain available until the kernel shuts down. The same expectation exists for virtual machines, and it is up to the hypervisor/toolstack to fulfill this expectation for the lifetime of the virtual machine, including across migrate/suspend/resume.


============
User Details
============

Many factors affect the set of features which a VM may use:

* The CPU itself
* The BIOS/firmware/microcode version and settings
* The hypervisor version and command line settings
* Further restrictions the toolstack chooses to apply

A firmware or software upgrade might reduce the available set of features, for example, Intel |reg| disabling TSX in a microcode update for certain Haswell/Broadwell processors). The available set of features may also be reduced by editing the settings.

It is unsafe to make any assumptions about features remaining consistent across a host reboot. Xen recalculates all information from scratch at each boot, and provides the information for the toolstack to consume.

`xl` currently has no facilities to help the user collect appropriate feature information from relevant hosts and compute appropriate feature specifications for use in host or domain configurations.  (`xl` being a single-host toolstack, it would in any case need external support for accessing remote hosts, for example, via SSH, in the form of automation software like GNU parallel or ansible.)

=================
Technical Details
=================

The `CPUID` instruction is used by softwares to query for features.  In the virtualisation usecase, guest software should query Xen rather than hardware directly.  However, `CPUID` is an unprivileged instruction which does not fault, complicating the task of hiding hardware features from guests.

Important files:

* Hypervisor
    * `xen/arch/x86/cpu/*.c`
    * `xen/arch/x86/cpuid.c`
    * `xen/include/asm-x86/cpuid-autogen.h`
    * `xen/include/public/arch-x86/cpufeatureset.h`
    * `xen/tools/gen-cpuid.py`
* `libxc`
    * `tools/libxc/xc_cpuid_x86.c`


Controlling CPUID
~~~~~~~~~~~~~~~~~

HVM
---

HVM guests (using `Intel VT-x` or `AMD SVM`) will unconditionally exit to Xen on all `CPUID` instructions, allowing Xen full control over all information.

PV
---

The `CPUID` instruction is unprivileged, so executing it in a PV guest will not trap, leaving Xen no direct ability to control the information returned.

Xen Forced Emulation Prefix
---------------------------

Xen-aware PV software can make use of the 'Forced Emulation Prefix'

> `ud2a; .ascii 'xen'; cpuid`

which Xen recognises as a deliberate attempt to get the fully-controlled `CPUID` information rather than the hardware-reported information. This only works with cooperative software.

Masking and Override MSRs
-------------------------

AMD CPUs from the `K8` onwards support _Feature Override_ MSRs, which allow direct control of the values returned for certain `CPUID` leaves.  These MSRs allow any result to be returned, including the ability to advertise features which are not actually supported.

Intel CPUs between `Nehalem` and `SandyBridge` have differing numbers of _Feature Mask_ MSRs, which are a simple AND-mask applied to all `CPUID` instructions requesting specific feature bitmap sets. The exact MSRs, and which feature bitmap sets they affect are hardware specific. These MSRs allow features to be hidden by clearing the appropriate bit in the mask, but does not allow unsupported features to be advertised.

CPUID Faulting
--------------

Intel CPUs from `IvyBridge` onwards have _CPUID Faulting_, which allows Xen to cause `CPUID` instruction executed in PV guests to fault.  This allows Xen full control over all information, exactly like HVM guests.

Compile time
------------

As some features depend on other features, it is important that, when disabling a certain feature, we disable all features which depend on it. This allows runtime logic to be simplified, by being able to rely on testing only the single appropriate feature, rather than the entire feature dependency chain.

To speed up runtime calculation of feature dependencies, the dependency chain is calculated and flattened by `xen/tools/gen-cpuid.py` to create `xen/include/asm-x86/cpuid-autogen.h` from `xen/include/public/arch-x86/cpufeatureset.h`, allowing the runtime code to disable all dependent features of a specific disabled feature in constant time.

=========
Host Boot
=========

As Xen boots, it will enumerate the features it can see. This is stored as the *raw_featureset*.

Errata checks and command line arguments are then taken into account to reduce the *raw_featureset* into the *host_featureset*, which is the set of features Xen uses. On hardware with masking/override MSRs, the default MSR values are picked from the *host_featureset*.

The *host_featureset* is then used to calculate the *pv_featureset* and *hvm_featureset*, which are the maximum featuresets Xen is willing to offer to PV and HVM guests respectively.

In addition, Xen will calculate how much control it has over non-cooperative PV `CPUID` instructions, storing this information as *levelling_caps*.

===============
Domain Creation
===============

The toolstack can query each of the calculated featureset via `XEN_SYSCTL_get_cpu_featureset`, and query for the levelling caps via
`XEN_SYSCTL_get_cpu_levelling_caps`.

These data should be used by the toolstack when choosing the eventual featureset to offer to the guest.

Once a featureset has been chosen, it is set (implicitly or explicitly) via `XEN_DOMCTL_set_cpuid`. Xen will clamp the toolstacks choice to the appropriate PV or HVM featureset. On hardware with masking/override MSRs, the guest cpuid policy is reflected in the MSRs, which are context switched with other vcpu state.

===========
Limitations
===========

A guest which ignores the provided feature information and manually probes for features will be able to find some of them.  e.g. There is no way of forcibly preventing a guest from using 1GB superpages if the hardware supports it.

Some information simply cannot be hidden from guests.  There is no way to control certain behaviour such as the hardware MXCSR_MASK or x87 FPU exception behaviour.

=======
Testing
=======

Feature levelling is a very wide area, and used all over the hypervisor. Ask on xen-devel for help identifying more specific tests which could be of use.

====================================
Known issues / Areas for improvement
====================================

The feature querying and levelling functions should exposed in a convenient-to-use way by `xl`.

Xen currently has no concept of per-{socket,core,thread} CPUID information. As a result, details such as APIC IDs, topology and cache information do not match real hardware, and do not match the documented expectations in the Intel and AMD system manuals.

The CPU feature flags are the only information which the toolstack has a sensible interface for querying and levelling. Other information in the CPUID policy is important and should be levelled (for example, maxphysaddr).

The CPUID policy is currently regenerated from scratch by the receiving side, once memory and vcpu content has been restored. This means that the receiving Xen cannot verify the memory/vcpu content against the CPUID policy, and can end up running a guest which will subsequently crash. The CPUID policy should be at the head of the migration stream.

MSRs are another source of features for guests. There is no general provision for controlling the available MSRs, for example, 64-bit versions of Windows notice changes in IA32_MISC_ENABLE, and suffer a BSOD 0x109 (Critical Structure Corruption).


==========
References
==========

- `Intel Flexmigration <http://www.intel.co.uk/content/dam/www/public/us/en/documents/application-notes/virtualization-technology-flexmigration-application-note.pdf>`__
- `AMD Extended Migration Technology <http://developer.amd.com/wordpress/media/2012/10/43781-3.00-PUB_Live-Virtual-Machine-Migration-on-AMD-processors.pdf>`__

=========
Changelog
=========

+-------------+----------------------------+-------------------------------------+
|  Date       |  Revision Version          |   Notes                             |
+=============+============================+=====================================+
| 2016-05-31  |     Xen 4.7                |        Document written             |
+-------------+----------------------------+-------------------------------------+
