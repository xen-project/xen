
#define __KERNEL_SYSCALLS__
static int errno;
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/dom0_ops.h>
#include <asm-xen/linux-public/suspend.h>
#include <asm-xen/queues.h>

void machine_restart(char * __unused)
{
	/* We really want to get pending console data out before we die. */
	extern void xencons_force_flush(void);
	xencons_force_flush();
	HYPERVISOR_reboot();
}

void machine_halt(void)
{
	machine_power_off();
}

void machine_power_off(void)
{
	/* We really want to get pending console data out before we die. */
	extern void xencons_force_flush(void);
	xencons_force_flush();
	HYPERVISOR_shutdown();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
int reboot_thru_bios = 0;	/* for dmi_scan.c */
EXPORT_SYMBOL(machine_restart);
EXPORT_SYMBOL(machine_halt);
EXPORT_SYMBOL(machine_power_off);
#endif


/******************************************************************************
 * Stop/pickle callback handling.
 */

/* Ignore multiple shutdown requests. */
static int shutting_down = -1;
static int pending_sysrq = -1;

static void __do_suspend(void)
{
    int i, j;
    suspend_record_t *suspend_record;

    /* Hmmm... a cleaner interface to suspend/resume blkdevs would be nice. */
	/* XXX SMH: yes it would :-( */	
#ifdef CONFIG_XEN_BLKDEV_FRONTEND
    extern void blkdev_suspend(void);
    extern void blkdev_resume(void);
#else
#define blkdev_suspend() do{}while(0)
#define blkdev_resume()  do{}while(0)
#endif

#ifdef CONFIG_XEN_NETDEV_FRONTEND
    extern void netif_suspend(void);
    extern void netif_resume(void);  
#else
#define netif_suspend() do{}while(0)
#define netif_resume()  do{}while(0)
#endif

    extern void time_suspend(void);
    extern void time_resume(void);
    extern unsigned long max_pfn;
    extern unsigned long *pfn_to_mfn_frame_list;

    suspend_record = (suspend_record_t *)__get_free_page(GFP_KERNEL);
    if ( suspend_record == NULL )
        goto out;

    suspend_record->nr_pfns = max_pfn; /* final number of pfns */

    __cli();

    netif_suspend();

    blkdev_suspend();

    time_suspend();

    ctrl_if_suspend();

    irq_suspend();

    HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
    clear_fixmap(FIX_SHARED_INFO);

    memcpy(&suspend_record->resume_info, &xen_start_info, sizeof(xen_start_info));

    HYPERVISOR_suspend(virt_to_machine(suspend_record) >> PAGE_SHIFT);

    HYPERVISOR_vm_assist(VMASST_CMD_enable,
			 VMASST_TYPE_4gb_segments);
#ifdef CONFIG_XEN_WRITABLE_PAGETABLES
    HYPERVISOR_vm_assist(VMASST_CMD_enable,
			 VMASST_TYPE_writable_pagetables);
#endif

    shutting_down = -1; 

    memcpy(&xen_start_info, &suspend_record->resume_info, sizeof(xen_start_info));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    set_fixmap_ma(FIX_SHARED_INFO, xen_start_info.shared_info);
#else
    set_fixmap(FIX_SHARED_INFO, xen_start_info.shared_info);
#endif

    HYPERVISOR_shared_info = (shared_info_t *)fix_to_virt(FIX_SHARED_INFO);

    memset(empty_zero_page, 0, PAGE_SIZE);

    for ( i=0, j=0; i < max_pfn; i+=(PAGE_SIZE/sizeof(unsigned long)), j++ )
    {
        pfn_to_mfn_frame_list[j] = 
            virt_to_machine(&phys_to_machine_mapping[i]) >> PAGE_SHIFT;
    }
    HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list =
        virt_to_machine(pfn_to_mfn_frame_list) >> PAGE_SHIFT;


    irq_resume();

    ctrl_if_resume();

    time_resume();

    blkdev_resume();

    netif_resume();

    __sti();

 out:
    if ( suspend_record != NULL )
        free_page((unsigned long)suspend_record);
}

static int shutdown_process(void *__unused)
{
    static char *envp[] = { "HOME=/", "TERM=linux", 
                            "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    static char *restart_argv[]  = { "/sbin/shutdown", "-r", "now", NULL };
    static char *poweroff_argv[] = { "/sbin/halt",     "-p",        NULL };

    extern asmlinkage long sys_reboot(int magic1, int magic2,
                                      unsigned int cmd, void *arg);

    daemonize(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        "shutdown"
#endif
        );

    switch ( shutting_down )
    {
    case CMSG_SHUTDOWN_POWEROFF:
        if ( execve("/sbin/halt", poweroff_argv, envp) < 0 )
        {
            sys_reboot(LINUX_REBOOT_MAGIC1,
                       LINUX_REBOOT_MAGIC2,
                       LINUX_REBOOT_CMD_POWER_OFF,
                       NULL);
        }
        break;

    case CMSG_SHUTDOWN_REBOOT:
        if ( execve("/sbin/shutdown", restart_argv, envp) < 0 )
        {
            sys_reboot(LINUX_REBOOT_MAGIC1,
                       LINUX_REBOOT_MAGIC2,
                       LINUX_REBOOT_CMD_RESTART,
                       NULL);
        }
        break;
    }

    shutting_down = -1; /* could try again */

    return 0;
}

static void __shutdown_handler(void *unused)
{
    int err;

    if ( shutting_down != CMSG_SHUTDOWN_SUSPEND )
    {
        err = kernel_thread(shutdown_process, NULL, CLONE_FS | CLONE_FILES);
        if ( err < 0 )
            printk(KERN_ALERT "Error creating shutdown process!\n");
    }
    else
    {
        __do_suspend();
    }
}

static void __sysrq_handler(void *unused)
{
#ifdef CONFIG_MAGIC_SYSRQ
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    handle_sysrq(pending_sysrq, NULL, NULL);
#else
    handle_sysrq(pending_sysrq, NULL, NULL, NULL);
#endif
#endif
    pending_sysrq = -1;
}

static void shutdown_handler(ctrl_msg_t *msg, unsigned long id)
{
    static DECLARE_WORK(shutdown_work, __shutdown_handler, NULL);
    static DECLARE_WORK(sysrq_work, __sysrq_handler, NULL);

    if ( (shutting_down == -1) &&
         ((msg->subtype == CMSG_SHUTDOWN_POWEROFF) ||
          (msg->subtype == CMSG_SHUTDOWN_REBOOT) ||
          (msg->subtype == CMSG_SHUTDOWN_SUSPEND)) )
    {
        shutting_down = msg->subtype;
        schedule_work(&shutdown_work);
    }
    else if ( (pending_sysrq == -1) && 
              (msg->subtype == CMSG_SHUTDOWN_SYSRQ) )
    {
        pending_sysrq = msg->msg[0];
        schedule_work(&sysrq_work);
    }
    else
    {
        printk("Ignore spurious shutdown request\n");
    }

    ctrl_if_send_response(msg);
}

static int __init setup_shutdown_event(void)
{
    ctrl_if_register_receiver(CMSG_SHUTDOWN, shutdown_handler, 0);
    return 0;
}

__initcall(setup_shutdown_event);
