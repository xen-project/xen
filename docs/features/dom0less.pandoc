Dom0less
========

"Dom0less" is a set of Xen features that enable the deployment of a Xen
system without an control domain (often referred to as "dom0"). Each
feature can be used independently from the others, unless otherwise
stated.

Booting Multiple Domains from Device Tree
-----------------------------------------

This feature enables Xen to create a set of DomUs at boot time.
Information about the DomUs to be created by Xen is passed to the
hypervisor via Device Tree. Specifically, the existing Device Tree based
Multiboot specification has been extended to allow for multiple domains
to be passed to Xen. See docs/misc/arm/device-tree/booting.txt for more
information about the Multiboot specification and how to use it.

Currently, a control domain ("dom0") is still required, but in the
future it will become unnecessary when all domains are created
directly from Xen. Instead of waiting for the control domain to be fully
booted and the Xen tools to become available, domains created by Xen
this way are started right away in parallel. Hence, their boot time is
typically much shorter.

Domains started by Xen at boot time currently have the following
limitations:

- They cannot be properly shutdown or rebooted using xl. If one of them
  crashes, the whole platform should be rebooted.

- Some xl operations might not work as expected. xl is meant to be used
  with domains that have been created by it. Using xl with domains
  started by Xen at boot might not work as expected.

- The GIC version is the native version. In absence of other
  information, the GIC version exposed to the domains started by Xen at
  boot is the same as the native GIC version.

- No PV drivers. There is no support for PV devices at the moment. All
  devices need to be statically assigned to guests.

- Pinning vCPUs of domains started by Xen at boot can be
  done from the control domain, using `xl vcpu-pin` as usual. It is not
  currently possible to configure vCPU pinning without a control domain.
  However, the NULL scheduler can be selected by passing `sched=null` to
  the Xen command line. The NULL scheduler automatically assigns and
  pins vCPUs to pCPUs, but the vCPU-pCPU assignments cannot be
  configured.
