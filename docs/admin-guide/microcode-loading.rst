Microcode Loading
=================

Like many other pieces of hardware, CPUs themselves have errata which are
discovered after shipping, and need to be addressed in the field.  Microcode
can be considered as firmware for the processor, and updates are published as
needed by the CPU vendors.

Microcode is included as part of the system firmware by an OEM, and a system
firmware update is the preferred way of obtaining updated microcode.  However,
this is often not the most expedient way to get updates, so Xen supports
loading microcode itself.

Distros typically package microcode updates for users, and may provide hooks
to cause microcode to be automatically loaded at boot time.  Consult your dom0
distro guidance for microcode loading.

Microcode can make almost arbitrary changes to the processor, including to
software visible features.  This includes removing features (e.g. the Haswell
TSX errata which necessitated disabling the feature entirely), or the addition
of brand new features (e.g. the Spectre v2 controls to work around speculative
execution vulnerabilities).


Boot time microcode loading
---------------------------

Where possible, microcode should be loaded at boot time.  This allows the CPU
to be updated to its eventual configuration before Xen starts making setup
decisions based on the visible features.

Xen will report during boot if it performed a microcode update::

  [root@host ~]# xl dmesg | grep microcode
  (XEN) microcode: CPU0 updated from revision 0x1a to 0x25, date = 2018-04-02
  (XEN) microcode: CPU2 updated from revision 0x1a to 0x25, date = 2018-04-02
  (XEN) microcode: CPU4 updated from revision 0x1a to 0x25, date = 2018-04-02
  (XEN) microcode: CPU6 updated from revision 0x1a to 0x25, date = 2018-04-02

The exact details printed are system and microcode specific.  After boot, the
current microcode version can obtained from with dom0::

  [root@host ~]# head /proc/cpuinfo
  processor    : 0
  vendor_id    : GenuineIntel
  cpu family   : 6
  model        : 60
  model name   : Intel(R) Xeon(R) CPU E3-1240 v3 @ 3.40GHz
  stepping     : 3
  microcode    : 0x25
  cpu MHz      : 3392.148
  cache size   : 8192 KB
  physical id  : 0


Loading microcode from a single file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Xen handles microcode blobs in the binary form shipped by vendors, which is
also the format which the processor accepts.  This format contains header
information which Xen and various userspace tools can use to identify the
correct blob for a specific CPU.

Tools such as Dracut will identify the correct blob for the current CPU, which
will be a few kilobytes, for minimal overhead during boot.

Additionally, Xen is capable of handling a number of blobs concatenated
together, and will locate the appropriate blob based on the header
information.

This option is less efficient during boot, but may be preferred in situations
where the exact CPU details aren't known ahead of booting (e.g. install
media).

The file containing the blob(s) needs to be accessible to Xen as early as
possible.

* For multiboot/multiboot2 boots, this is achieved by loading the file as a
  multiboot module.  The ``ucode=$num`` command line option can be used to
  identify which multiboot module contains the microcode, including negative
  indexing to count from the end.

* For EFI boots, there isn't really a concept of modules.  A microcode file
  can be specified in the EFI configuration file with ``ucode=$file``.  Use of
  this mechanism will override any ``ucode=`` settings on the command line.


Loading microcode from a Linux initrd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For systems using a Linux based dom0, it usually suffices to install the
appropriate distro package, and add ``ucode=scan`` to Xen's command line.

Xen is compatible with the Linux initrd microcode protocol.  The initrd is
expected to be generated with an uncompressed CPIO archive at the beginning
which contains contains one of these two files::

  kernel/x86/microcode/GenuineIntel.bin
  kernel/x86/microcode/AuthenticAMD.bin

The ``ucode=scan`` command line option will cause Xen to search through all
modules to find any CPIO archives, and search the archive for the applicable
file.  Xen will stop searching at the first match.


Run time microcode loading
--------------------------

.. warning::

   If at all possible, microcode updates should be done by firmware updates,
   or at boot time.  Not all microcode updates (or parts thereof) can be
   applied at runtime.

The ``xen-ucode`` utility can be used to initiate a runtime microcode load.
It will pass the blob to Xen, which will check to see whether the blob is
correct for the processor, and newer than the running microcode.

If these checks pass, the entire system will be rendezvoused and an update
will be initiated on all CPUs in parallel.  As with boot time loading,
diagnostics will be put out onto the console::

  [root@host ~]# xl dmesg | grep microcode
  (XEN) microcode: CPU0 updated from revision 0x1a to 0x25, date = 2018-04-02
  (XEN) microcode: CPU2 updated from revision 0x1a to 0x25, date = 2018-04-02
  (XEN) microcode: CPU4 updated from revision 0x1a to 0x25, date = 2018-04-02
  (XEN) microcode: CPU6 updated from revision 0x1a to 0x25, date = 2018-04-02
  (XEN) 4 cores are to update their microcode
  (XEN) microcode: CPU0 updated from revision 0x25 to 0x27, date = 2019-02-26
  (XEN) microcode: CPU4 updated from revision 0x25 to 0x27, date = 2019-02-26
  (XEN) microcode: CPU2 updated from revision 0x25 to 0x27, date = 2019-02-26
  (XEN) microcode: CPU6 updated from revision 0x25 to 0x27, date = 2019-02-26
