/******************************************************************************
 * arch/x86/paging.c
 *
 * x86 specific paging support
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Copyright (c) 2007 XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/init.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hap.h>

/* Xen command-line option to enable hardware-assisted paging */
int opt_hap_enabled;
boolean_param("hap", opt_hap_enabled);

/* Printouts */
#define PAGING_PRINTK(_f, _a...)                                     \
    debugtrace_printk("pg: %s(): " _f, __func__, ##_a)
#define PAGING_ERROR(_f, _a...)                                      \
    printk("pg error: %s(): " _f, __func__, ##_a)
#define PAGING_DEBUG(flag, _f, _a...)                                \
    do {                                                             \
        if (PAGING_DEBUG_ ## flag)                                   \
            debugtrace_printk("pgdebug: %s(): " _f, __func__, ##_a); \
    } while (0)


/* Domain paging struct initialization. */
void paging_domain_init(struct domain *d)
{
    p2m_init(d);
    shadow_domain_init(d);

    if ( opt_hap_enabled && is_hvm_domain(d) )
        hap_domain_init(d);
}

/* vcpu paging struct initialization goes here */
void paging_vcpu_init(struct vcpu *v)
{
    if ( opt_hap_enabled && is_hvm_vcpu(v) )
        hap_vcpu_init(v);
    else
        shadow_vcpu_init(v);
}


int paging_domctl(struct domain *d, xen_domctl_shadow_op_t *sc,
                  XEN_GUEST_HANDLE(void) u_domctl)
{
    /* Here, dispatch domctl to the appropriate paging code */
    if ( opt_hap_enabled && is_hvm_domain(d) )
        return hap_domctl(d, sc, u_domctl);
    else
        return shadow_domctl(d, sc, u_domctl);
}

/* Call when destroying a domain */
void paging_teardown(struct domain *d)
{
    if ( opt_hap_enabled && is_hvm_domain(d) )
        hap_teardown(d);
    else
        shadow_teardown(d);
}

/* Call once all of the references to the domain have gone away */
void paging_final_teardown(struct domain *d)
{
    if ( opt_hap_enabled && is_hvm_domain(d) )
        hap_final_teardown(d);
    else
        shadow_final_teardown(d);
}

/* Enable an arbitrary paging-assistance mode.  Call once at domain
 * creation. */
int paging_enable(struct domain *d, u32 mode)
{
    if ( opt_hap_enabled && is_hvm_domain(d) )
        return hap_enable(d, mode | PG_HAP_enable);
    else
        return shadow_enable(d, mode | PG_SH_enable);
}

/* Print paging-assistance info to the console */
void paging_dump_domain_info(struct domain *d)
{
    if ( paging_mode_enabled(d) )
    {
        printk("    paging assistance: ");
        if ( paging_mode_shadow(d) )
            printk("shadow ");
        if ( paging_mode_hap(d) )
            printk("hap ");
        if ( paging_mode_refcounts(d) )
            printk("refcounts ");
        if ( paging_mode_log_dirty(d) )
            printk("log_dirty ");
        if ( paging_mode_translate(d) )
            printk("translate ");
        if ( paging_mode_external(d) )
            printk("external ");
        printk("\n");
    }
}

void paging_dump_vcpu_info(struct vcpu *v)
{
    if ( paging_mode_enabled(v->domain) )
    {
        printk("    paging assistance: ");        
        if ( paging_mode_shadow(v->domain) )
        {
            if ( v->arch.paging.mode )
                printk("shadowed %u-on-%u, %stranslated\n",
                       v->arch.paging.mode->guest_levels,
                       v->arch.paging.mode->shadow.shadow_levels,
                       paging_vcpu_mode_translate(v) ? "" : "not ");
            else
                printk("not shadowed\n");
        }
        else if ( paging_mode_hap(v->domain) && v->arch.paging.mode )
            printk("hap, %u levels\n", 
                   v->arch.paging.mode->guest_levels);
        else
            printk("none\n");
    }
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
