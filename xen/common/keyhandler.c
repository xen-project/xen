
#include <xen/keyhandler.h> 
#include <xen/reboot.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#define KEY_MAX 256
#define STR_MAX  64

static struct { 
    key_handler *handler;
    int          flags;
    char         desc[STR_MAX]; 
} key_table[KEY_MAX]; 

#define KEYHANDLER_NO_DEFER 0x1

static unsigned char keypress_key;

void keypress_softirq(void)
{
    key_handler  *h;
    unsigned char key = keypress_key;
    if ( (h = key_table[key].handler) != NULL )
        (*h)(key);
}

void handle_keypress(unsigned char key, struct xen_regs *regs)
{
    key_handler  *h;

    keypress_key = key;
    if ( (key_table[key].flags & KEYHANDLER_NO_DEFER) &&
         ((h = key_table[key].handler) != NULL) )
        ((void (*)(unsigned char, struct xen_regs *))*h)(key, regs);
    else
        raise_softirq(KEYPRESS_SOFTIRQ);
}

void add_key_handler(unsigned char key, key_handler *handler, char *desc)
{
    key_table[key].handler = handler;
    key_table[key].flags = 0;
    strncpy(key_table[key].desc, desc, STR_MAX);
    key_table[key].desc[STR_MAX-1] = '\0'; 
}

void add_key_handler_no_defer(unsigned char key, key_handler *handler,
                              char *desc)
{
    add_key_handler(key, handler, desc);
    key_table[key].flags |= KEYHANDLER_NO_DEFER;
}

static void show_handlers(unsigned char key)
{
    int i; 
    printk("'%c' pressed -> showing installed handlers\n", key);
    for ( i = 0; i < KEY_MAX; i++ ) 
        if ( key_table[i].handler != NULL ) 
            printk(" key '%c' (ascii '%02x') => %s\n", 
                   (i<33 || i>126)?(' '):(i),i,
                   key_table[i].desc);
}


static void dump_registers(unsigned char key)
{
    struct xen_regs *regs = (struct xen_regs *)get_execution_context();
    extern void show_registers(struct xen_regs *regs); 
    printk("'%c' pressed -> dumping registers\n", key); 
    show_registers(regs); 
}

static void halt_machine(unsigned char key)
{
    printk("'%c' pressed -> rebooting machine\n", key); 
    machine_restart(NULL); 
}

void do_task_queues(unsigned char key)
{
    struct domain *d;
    struct exec_domain *ed;
    s_time_t       now = NOW();
    struct list_head *ent;
    struct pfn_info  *page;

    printk("'%c' pressed -> dumping task queues (now=0x%X:%08X)\n", key,
           (u32)(now>>32), (u32)now); 

    read_lock(&domlist_lock);

    for_each_domain ( d )
    {
        printk("Xen: DOM %u, flags=%lx refcnt=%d nr_pages=%d "
               "xenheap_pages=%d\n", d->id, d->d_flags,
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
               
        for_each_exec_domain ( d, ed ) {
            printk("Guest: %p CPU %d [has=%c] flags=%lx "
                   "upcall_pend = %02x, upcall_mask = %02x\n", ed,
                   ed->processor,
                   test_bit(EDF_RUNNING, &ed->ed_flags) ? 'T':'F',
                   ed->ed_flags,
                   ed->vcpu_info->evtchn_upcall_pending, 
                   ed->vcpu_info->evtchn_upcall_mask);
            printk("Notifying guest... %d/%d\n", d->id, ed->eid); 
            printk("port %d/%d stat %d %d %d\n",
                   VIRQ_DEBUG, ed->virq_to_evtchn[VIRQ_DEBUG],
                   test_bit(ed->virq_to_evtchn[VIRQ_DEBUG], &d->shared_info->evtchn_pending[0]),
                   test_bit(ed->virq_to_evtchn[VIRQ_DEBUG], &d->shared_info->evtchn_mask[0]),
                   test_bit(ed->virq_to_evtchn[VIRQ_DEBUG]>>5, &ed->vcpu_info->evtchn_pending_sel));
            send_guest_virq(ed, VIRQ_DEBUG);
        }
    }

    read_unlock(&domlist_lock);
}

extern void dump_runq(unsigned char key);
extern void print_sched_histo(unsigned char key);
extern void reset_sched_histo(unsigned char key);
#ifndef NDEBUG
extern void audit_domains_key(unsigned char key);
#endif

#ifdef PERF_COUNTERS
extern void perfc_printall(unsigned char key);
extern void perfc_reset(unsigned char key);
#endif

void initialize_keytable(void)
{
    open_softirq(KEYPRESS_SOFTIRQ, keypress_softirq);

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
