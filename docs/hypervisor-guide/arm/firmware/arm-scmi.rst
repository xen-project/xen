.. SPDX-License-Identifier: CC-BY-4.0

ARM System Control and Management Interface (SCMI)
==================================================

The System Control and Management Interface (SCMI) [1], which is a set
of operating system-independent software interfaces that are used in
system management. SCMI currently
provides interfaces for:

- Discovery and self-description of the interfaces it supports
- Power domain management
- Clock management
- Reset domain management
- Voltage domain management
- Sensor management
- Performance management
- Power capping and monitoring
- Pin control protocol.

The SCMI compliant firmware could run:

- as part of EL3 secure world software (like Trusted Firmware-A) with
  ARM SMC shared-memory transport;
- on dedicated System Control Processor (SCP) with HW mailbox
  shared-memory transport

The major purpose of enabling SCMI support in Xen is to enable guest
domains access to the SCMI interfaces for performing management actions
on passed-through devices (such as clocks/resets etc) without accessing
directly to the System control HW (like clock controllers) which in most
cases can't be shared/split between domains. Or, at minimum, allow SCMI
access for dom0/hwdom (or guest domain serving as Driver domain).

The below sections describe SCMI support options available for Xen.

| [1] `Arm SCMI <https://developer.arm.com/documentation/den0056/latest/>`_
| [2] `System Control and Management Interface (SCMI) bindings <https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/devicetree/bindings/firmware/arm,scmi.yaml>`_

Simple SCMI over SMC calls forwarding driver (EL3)
------------------------------------------------------

The EL3 SCMI firmware (TF-A) with a single SCMI OSPM agent support is
pretty generic case for the default vendors SDK and new platforms with
SCMI support. Such EL3 SCMI firmware supports only single SCMI OSPM
transport (agent) with Shared memory based transport and SMC calls as
doorbell.

The SCMI over SMC calls forwarding driver solves major problem for this
case by allowing SMC calls to be forwarded from guest to the EL3 SCMI
firmware.

By default, the SCMI over SMC calls forwarding is enabled for
Dom0/hwdom.

::

    +--------------------------+
    |                          |
    | EL3 SCMI FW (TF-A)       |
    ++-------+--^--------------+
     |shmem  |  | smc-id
     +----^--+  |
          |     |
     +----|-+---+---+----------+
     |    | |  FWD  |      Xen |
     |    | +---^---+          |
     +----|-----|--------------+
          |     | smc-id
     +----v-----+--+ +---------+
     |             | |         |
     | Dom0/hwdom  | | DomU    |
     |             | |         |
     |             | |         |
     +-------------+ +---------+


The SCMI messages are passed directly through SCMI shared-memory
(zero-copy) and driver only forwards SMC calls.

Compiling
^^^^^^^^^

To build with the SCMI over SMC calls forwarding enabled support, enable
Kconfig option

::

    SCMI_SMC

The ``CONFIG_SCMI_SMC`` is enabled by default.

Pass-through SCMI SMC to domain which serves as Driver domain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This section describes how to configure the SCMI over SMC calls
forwarding driver to handle use case "thin Dom0 with guest domain, which
serves as Driver domain". In this case HW need to be enabled in Driver
domain and dom0 is performing only control functions (without accessing
FW) and so, the SCMI need to be enabled in Driver domain.

::

     +--------------------------+
     |EL3 SCMI FW (TF-A)        |
     |                          |
     +-------------^--+-------+-+
             smc-id|  |shmem0 |
                   |  +----^--+
    +-------------++------+|----+
    |Xen          |  FWD  ||    |
    |             +--^----+|    |
    +----------------|-----|----+
              smc-id |     |
    +-----------+ +--+-----v-----+
    |           | |              |
    | Dom0      | |    Driver    |
    | Control   | |    domain    |
    |           | |              |
    +-----------+ +--------------+

The SCMI can be enabled for one and only one guest domain.

First, configure Dom0 to enable SCMI pass-through using Xen Command Line
**"scmi-smc-passthrough"** option. This will disable SCMI for Dom0/hwdom
and SCMI nodes will be removed from Dom0/hwdom device tree.

**Configure SCMI pass-through for guest domain with toolstack**

* In domain's xl.cfg file add **"arm_sci"** option as below

::

    arm_sci = "type=scmi_smc"

* In domain's xl.cfg file enable access to the "arm,scmi-shmem"

::

    iomem = [
        "47ff0,1@22001",
    ]

.. note:: It's up to the user to select guest IPA for mapping SCMI shared-memory.

* Add SCMI nodes to the Driver domain partial device tree as in the
  below example:

.. code::

    passthrough {
       scmi_shm_0: sram@22001000 {
           compatible = "arm,scmi-shmem";
           reg = <0x0 0x22001000 0x0 0x1000>;
       };

       firmware {
            compatible = "simple-bus";
                scmi: scmi {
                    compatible = "arm,scmi-smc";
                    shmem = <&scmi_shm_0>;
                    ...
                }
        }
    }

Please refer to [2] for details of SCMI DT bindings.

In general, the configuration is similar to any other HW pass-through,
except explicitly enabling SCMI with "arm_sci" xl.cfg option.

**Configure SCMI pass-through for predefined domain (dom0less)**

* add "xen,sci_type" property for required DomU ("xen,domain") node

::

       xen,sci_type="scmi_smc"

* add scmi nodes to the Driver domain partial device tree the same way
  as above and enable access to the "arm,scmi-shmem" according to
  dom0less documentation. For example:

.. code::

      scmi_shm_0: sram@22001000 {
            compatible = "arm,scmi-shmem";
            reg = <0x00 0x22001000 0x00 0x1000>;
    ->        xen,reg = <0x0 0x47ff0000 0x0 0x1000 0x0 0x22001000>;
    ->        xen,force-assign-without-iommu;
      };
