/******************************************************************************
 * arch-x86/guest-acpi.h
 *
 * Guest ACPI interface to x86 Xen.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef __XEN_PUBLIC_ARCH_X86_GUEST_ACPI_H__
#define __XEN_PUBLIC_ARCH_X86_GUEST_ACPI_H__

#ifdef __XEN_TOOLS__

/* Location of online VCPU bitmap. */
#define XEN_ACPI_CPU_MAP             0xaf00
#define XEN_ACPI_CPU_MAP_LEN         ((HVM_MAX_VCPUS + 7) / 8)

/* GPE0 bit set during CPU hotplug */
#define XEN_ACPI_GPE0_CPUHP_BIT      2

#endif /* __XEN_TOOLS__ */

#endif /* __XEN_PUBLIC_ARCH_X86_GUEST_ACPI_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
