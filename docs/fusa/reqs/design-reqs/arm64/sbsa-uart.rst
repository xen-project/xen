.. SPDX-License-Identifier: CC-BY-4.0

SBSA UART
=========

The following are the requirements related to SBSA UART [1] emulated and
exposed by Xen to Arm64 domains.

Probe the UART device tree node from a domain
---------------------------------------------

`XenSwdgn~arm64_uart_probe_dt~1`

Description:
Xen shall generate a device tree node for the SBSA UART (in accordance to Arm
SBSA UART device tree binding [2]) in the domain device tree.

Rationale:

Comments:
Domains can detect the presence of the SBSA UART device tree node.

Covers:
 - `XenProd~arm64_emulated_uart~1`

Transmit data in software polling mode
--------------------------------------

`XenSwdgn~arm64_uart_transmit_data_poll_mode~1`

Description:
Xen shall support transmission of data in polling mode.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Transmit data in interrupt driven mode
--------------------------------------

`XenSwdgn~arm64_uart_transmit_data_interrupt_mode~1`

Description:
Xen shall support transmission of data in interrupt driven mode.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Receive data in software polling mode
-------------------------------------

`XenSwdgn~arm64_uart_receive_data_polling_mode~1`

Description:
Xen shall support reception of data in polling mode.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Receive data in interrupt driven mode
-------------------------------------

`XenSwdgn~arm64_uart_receive_data_interrupt_mode~1`

Description:
Xen shall support reception of data in interrupt driven mode.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Access UART data register
-------------------------

`XenSwdgn~arm64_uart_access_data_register~1`

Description:
Xen shall emulate the UARTDR register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Access UART receive status register
-----------------------------------

`XenSwdgn~arm64_uart_access_receive_status_register~1`

Description:
Xen shall emulate the UARTRSR register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Access UART flag register
-------------------------

`XenSwdgn~arm64_uart_access_flag_register~1`

Description:
Xen shall emulate the UARTFR register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Access UART mask set/clear register
-----------------------------------

`XenSwdgn~arm64_uart_access_mask_register~1`

Description:
Xen shall emulate the UARTIMSC register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Access UART raw interrupt status register
-----------------------------------------

`XenSwdgn~arm64_uart_access_raw_interrupt_status_register~1`

Description:
Xen shall emulate the UARTRIS register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Access UART masked interrupt status register
--------------------------------------------

`XenSwdgn~arm64_uart_access_mask_irq_status_register~1`

Description:
Xen shall emulate the UARTMIS register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Access UART interrupt clear register
------------------------------------

`XenSwdgn~arm64_uart_access_irq_clear_register~1`

Description:
Xen shall emulate the UARTICR register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Receive UART TX interrupt
-------------------------

`XenSwdgn~arm64_uart_receive_tx_irq~1`

Description:
Xen shall generate UART interrupt when the UART transmit interrupt condition is
met.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

Receive UART RX interrupt reception
-----------------------------------

`XenSwdgn~arm64_uart_receive_rx_irq~1`

Description:
Xen shall generate UART interrupt when the UART receive interrupt condition is
met.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_uart~1`

[1] Arm Base System Architecture, chapter B
[2] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/devicetree/bindings/serial/arm_sbsa_uart.txt
