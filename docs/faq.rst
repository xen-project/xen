.. SPDX-License-Identifier: CC-BY-4.0

Frequently Asked Questions
==========================

How do I...
-----------

... check whether a Kconfig option is active?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  Kconfig is a build time configuration system, combining inherent knowledge,
  the capabilities of the toolchain, and explicit user choice to form a
  configuration of a build of Xen.

  A file, by default ``.config``, is produced by the build identifying the
  configuration used.  Kconfig symbols all start with ``CONFIG_``, and come in
  a variety of types including strings, integers and booleans.  Booleans are
  the most common, and when active are expressed with ``...=y``.  e.g.::

    xen.git/xen$ grep CONFIG_FOO .config
    CONFIG_FOO_BOOLEAN=y
    CONFIG_FOO_STRING="lorem ipsum"
    CONFIG_FOO_INTEGER=42

  Symbols which are either absent, or expressed as ``... is not set`` are
  disabled.  e.g.::

    xen.git/xen$ grep CONFIG_BAR .config
    # CONFIG_BAR is not set

  Builds of Xen configured with ``CONFIG_HYPFS_CONFIG=y`` embed their own
  ``.config`` at build time, and can provide it to the :term:`control domain`
  upon requested.  e.g.::

    [root@host ~]# xenhypfs cat /buildinfo/config | grep -e FOO -e BAR
    CONFIG_FOO=y
    # CONFIG_BAR is not set


... tell if CET is active?
^^^^^^^^^^^^^^^^^^^^^^^^^^

  Control-flow Enforcement Technology support was added to Xen 4.14.  It is
  build time conditional, dependent on both having a new-enough toolchain and
  an explicit Kconfig option, and also requires capable hardware.  See
  :term:`CET`.

  For CET-SS, Shadow Stacks, the minimum toolchain requirements are ``binutils
  >= 2.29`` or ``LLVM >= 6``.  No specific compiler support is required.
  Check for ``CONFIG_XEN_SHSTK`` being active.

  For CET-IBT, Indirect Branch Tracking, the minimum toolchain requirements
  are ``GCC >= 9`` and ``binutils >= 2.29``.  Xen relies on a compiler feature
  which is specific to GCC at the time of writing.  Check for
  ``CONFIG_XEN_IBT`` being active.

  If a capable Xen is booted on capable hardware, and CET is not disabled by
  command line option or errata, Xen will print some details early on boot
  about which CET facilities have been turned on::

    ...
    (XEN) CPU Vendor: Intel, Family 6 (0x6), Model 143 (0x8f), Stepping 8 (raw 000806f8)
    (XEN) Enabling Supervisor Shadow Stacks
    (XEN) Enabling Indirect Branch Tracking
    (XEN)   - IBT disabled in UEFI Runtime Services
    (XEN) EFI RAM map:
    ...

  This can be obtained from the control domain with ``xl dmesg``, but remember
  to confirm that the console ring hasn't wrapped.
