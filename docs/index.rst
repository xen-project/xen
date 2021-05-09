.. SPDX-License-Identifier: CC-BY-4.0

The Xen Hypervisor Documentation
================================

.. note::

   Xen's Sphinx/RST documentation is a work in progress. The existing
   documentation can be found at https://xenbits.xen.org/docs/

Xen is an open source, bare metal hypervisor.  It runs as the most privileged
piece of software on the system, and shares the resources of the hardware
between virtual machines.  See :doc:`admin-guide/introduction` for an
introduction to a Xen system.

.. toctree::
   :maxdepth: 4
   :caption: Introduction to Xen
   :hidden:
   
   introduction/introduction
   introduction/architecture
   introduction/installation
   introduction/features/index


.. toctree::
   :maxdepth: 4
   :caption: Tutorials
   :hidden:

   tutorials/configure-networking
   tutorials/reduce-latency
   tutorials/running-xen-on-arm/index


.. toctree::
   :maxdepth: 4
   :caption: How-to Guides
   :hidden:

   how-to/how-xen-boots
   how-to/code-coverage
   admin-guide/microcode-loading


.. toctree::
   :maxdepth: 4
   :caption: References
   :hidden:

   reference/hypercall-abi


.. toctree::
   :caption: Glossary
   :hidden:

   glossary


.. toctree::
   :maxdepth: 2
   :caption: FAQ

   faq/faq

.. toctree::
   :maxdepth: 2
   :caption: Contributing to the Xen Project

   contribute-xen/contribute-xen
   contribute-xen/submit-patch
