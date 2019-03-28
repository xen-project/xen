The Xen Hypervisor documentation
================================

.. note::

  Xen's Sphinx/RST documentation is a work in progress.  The existing
  documentation can be found at https://xenbits.xen.org/docs/


User documentation
------------------

This is documentation for an administrator of a Xen system.  It is intended
for someone who is not necesserily a developer, has installed Xen from their
preferred distribution, and is attempting to run virtual machines and
configure the system.

.. toctree::
  :maxdepth: 2

  admin-guide/index


Guest documentation
-------------------

This documentation concerns the APIs and ABIs available to guests.  It is
intended for OS developers trying to use a Xen feature, and for Xen developers
to avoid breaking things.

.. toctree::
  :maxdepth: 3

  guest-guide/index


Hypervisor developer documentation
----------------------------------

This is documentation for a hypervisor developer.  It is intended for someone
who is building Xen from source, and is running the new hypervisor in some
kind of development environment.

.. toctree::
  :maxdepth: 2

  hypervisor-guide/index
