
#include <xen/keyhandler.h> 
#include <xen/reboot.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/sched.h>

#define KEY_MAX 256
#define STR_MAX  64

static struct { 
    key_handler *handler; 
    char         desc[STR_MAX]; 
} key_table[KEY_MAX]; 

void add_key_handler(unsigned char key, key_handler *handler, char *desc)
{
    key_table[key].handler = handler; 
    strncpy(key_table[key].desc, desc, STR_MAX);
    key_table[key].desc[STR_MAX-1] = '\0'; 
}

key_handler *get_key_handler(unsigned char key)
{
    return key_table[key].handler; 
}

static void show_handlers(unsigned char key, void *dev_id,
                          struct pt_regs *regs)
{
    int i; 
    printk("'%c' pressed -> showing installed handlers\n", key);
    for ( i = 0; i < KEY_MAX; i++ ) 
        if ( key_table[i].handler != NULL ) 
            printk(" key '%c' (ascii '%02x') => %s\n", 
                   (i<33 || i>126)?(' '):(i),i,
                   key_table[i].desc);
}


static void dump_registers(unsigned char key, void *dev_id,
                           struct pt_regs *regs)
{
    extern void show_registers(struct pt_regs *regs); 
    printk("'%c' pressed -> dumping registers\n", key); 
    show_registers(regs); 
}

static void halt_machine(unsigned char key, void *dev_id,
                         struct pt_regs *regs) 
{
    printk("'%c' pressed -> rebooting machine\n", key); 
    machine_restart(NULL); 
}

void do_task_queues(unsigned char key, void *dev_id,
                    struct pt_regs *regs) 
{
    unsigned long  flags;
    struct domain *d;
    s_time_t       now = NOW();
    struct list_head *ent;
    struct pfn_info  *page;

    printk("'%c' pressed -> dumping task queues (now=0x%X:%08X)\n", key,
           (u32)(now>>32), (u32)now); 

    read_lock_irqsave(&tasklist_lock, flags); 

    for_each_domain ( d )
    {
        printk("Xen: DOM %u, CPU %d [has=%c] flags=%lx refcnt=%d nr_pages=%d "
               "xenheap_pages=%d\n",
               d->id, d->processor, 
               test_bit(DF_RUNNING, &d->flags) ? 'T':'F', d->flags,
               atomic_read(&d->refcnt), d->tot_pages, d->xenheap_pages);

        if ( d->tot_pages < 10 )
        {
            list_for_each ( ent, &d->page_list )
            {
                page = list_entry(ent, struct pfn_info, list);
                printk("Page %08x: caf=%08x, taf=%08x\n",
                       page_to_phys(page), page->count_info,
                       page->u.inuse.type_info);
            }
        }

        page = virt_to_page(d->shared_info);
        printk("Shared_info@%08x: caf=%08x, taf=%08x\n",
               page_to_phys(page), page->count_info,
               page->u.inuse.type_info);
               
        printk("Guest: upcall_pend = %02x, upcall_mask = %02x\n", 
               d->shared_info->vcpu_data[0].evtchn_upcall_pending, 
               d->shared_info->vcpu_data[0].evtchn_upcall_mask);
        printk("Notifying guest...\n"); 
        send_guest_virq(d, VIRQ_DEBUG);
    }

    read_unlock_irqrestore(&tasklist_lock, flags); 
}

extern void dump_runq(unsigned char key, void *dev_id, 
                      struct pt_regs *regs);
extern void print_sched_histo(unsigned char key, void *dev_id, 
                              struct pt_regs *regs);
extern void reset_sched_histo(unsigned char key, void *dev_id, 
                              struct pt_regs *regs);
#ifndef NDEBUG
extern void audit_domains_key(unsigned char key, void *dev_id,
                           struct pt_regs *regs);
#endif

#ifdef PERF_COUNTERS
extern void perfc_printall(unsigned char key, void *dev_id,
                           struct pt_regs *regs);
extern void perfc_reset(unsigned char key, void *dev_id,
                        struct pt_regs *regs);
#endif

void initialize_keytable(void)
{
    add_key_handler('d', dump_registers, "dump registers"); 
    add_key_handler('h', show_handlers, "show this message");
    add_key_handler('l', print_sched_histo, "print sched latency histogram");
    add_key_handler('L', reset_sched_histo, "reset sched latency histogram");
    add_key_handler('q', do_task_queues, "dump task queues + guest state");
    add_key_handler('r', dump_runq,      "dump run queues");
    add_key_handler('R', halt_machine,   "reboot machine"); 

#ifndef NDEBUG
    add_key_handler('o', audit_domains_key,  "audit domains >0 EXPERIMENTAL"); 
#endif

#ifdef PERF_COUNTERS
    add_key_handler('p', perfc_printall, "print performance counters"); 
    add_key_handler('P', perfc_reset,    "reset performance counters"); 
#endif
}
