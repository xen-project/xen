/*
 * ioreq.h: Hardware virtual machine assist interface definitions.
 *
 * Copyright (c) 2016 Citrix Systems Inc.
 * Copyright (c) 2019 Arm ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_ARM_IOREQ_H__
#define __ASM_ARM_IOREQ_H__

#ifdef CONFIG_IOREQ_SERVER
enum io_state handle_ioserv(struct cpu_user_regs *regs, struct vcpu *v);
enum io_state try_fwd_ioserv(struct cpu_user_regs *regs,
                             struct vcpu *v, mmio_info_t *info);
#else
static inline enum io_state handle_ioserv(struct cpu_user_regs *regs,
                                          struct vcpu *v)
{
    return IO_UNHANDLED;
}

static inline enum io_state try_fwd_ioserv(struct cpu_user_regs *regs,
                                           struct vcpu *v, mmio_info_t *info)
{
    return IO_UNHANDLED;
}
#endif

static inline bool handle_pio(uint16_t port, unsigned int size, int dir)
{
    /*
     * TODO: For Arm64, the main user will be PCI. So this should be
     * implemented when we add support for vPCI.
     */
    ASSERT_UNREACHABLE();
    return true;
}

static inline void msix_write_completion(struct vcpu *v)
{
}

/* This correlation must not be altered */
#define IOREQ_STATUS_HANDLED     IO_HANDLED
#define IOREQ_STATUS_UNHANDLED   IO_UNHANDLED
#define IOREQ_STATUS_RETRY       IO_RETRY

#endif /* __ASM_ARM_IOREQ_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
