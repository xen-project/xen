
#include <xeno/keyhandler.h> 
#include <xeno/reboot.h>
#include <xeno/event.h>
#include <xeno/console.h>
#include <xeno/serial.h>

#define KEY_MAX 256
#define STR_MAX  64

typedef struct _key_te { 
    key_handler *handler; 
    char         desc[STR_MAX]; 
} key_te_t; 

static key_te_t key_table[KEY_MAX]; 
    
void add_key_handler(u_char key, key_handler *handler, char *desc) 
{
    int i; 
    char *str; 

    if ( key_table[key].handler != NULL ) 
	printk("Warning: overwriting handler for key 0x%x\n", key); 

    key_table[key].handler = handler; 

    str = key_table[key].desc; 
    for ( i = 0; i < STR_MAX; i++ )
    {
	if ( *desc != '\0' ) 
	    *str++ = *desc++; 
	else
            break; 
    }
    if ( i == STR_MAX ) 
	key_table[key].desc[STR_MAX-1] = '\0'; 
}

key_handler *get_key_handler(u_char key)
{
    return key_table[key].handler; 
}

static void serial_rx(unsigned char c, struct pt_regs *regs)
{
    key_handler *handler;
    if ( (handler = get_key_handler(c)) != NULL )
        (*handler)(c, NULL, regs);
}

static void show_handlers(u_char key, void *dev_id, struct pt_regs *regs) 
{
    int i; 

    printk("'%c' pressed -> showing installed handlers\n", key); 
    for ( i = 0; i < KEY_MAX; i++ ) 
	if ( key_table[i].handler != NULL ) 
	    printk(" key '%c' (ascii '%02x') => %s\n", 
			(i<33 || i>126)?(' '):(i),i,
			key_table[i].desc);
}


static void dump_registers(u_char key, void *dev_id, struct pt_regs *regs) 
{
    extern void show_registers(struct pt_regs *regs); 
    printk("'%c' pressed -> dumping registers\n", key); 
    show_registers(regs); 
}

static void halt_machine(u_char key, void *dev_id, struct pt_regs *regs) 
{
    printk("'%c' pressed -> rebooting machine\n", key); 
    machine_restart(NULL); 
}

static void kill_dom0(u_char key, void *dev_id, struct pt_regs *regs) 
{
    printk("'%c' pressed -> gracefully rebooting machine\n", key); 
    kill_other_domain(0, 0);
}


/* XXX SMH: this is keir's fault */
static char *task_states[] = 
{ 
    "Runnable  ", 
    "Int Sleep ", 
    "UInt Sleep", 
    NULL,
    "Stopped   ", 
    NULL,
    NULL,
    NULL,
    "Dying     ", 
}; 

void do_task_queues(u_char key, void *dev_id, struct pt_regs *regs) 
{
    unsigned long       flags, cpu_mask = 0; 
    struct task_struct *p; 
    shared_info_t      *s; 
    s_time_t            now = NOW();

    printk("'%c' pressed -> dumping task queues (now=0x%X:%08X)\n", key,
           (u32)(now>>32), (u32)now); 

    read_lock_irqsave(&tasklist_lock, flags); 

    p = &idle0_task;
    do {
        printk("Xen: DOM %llu, CPU %d [has=%c], state = %s, "
               "hyp_events = %08x\n", 
               p->domain, p->processor, p->has_cpu ? 'T':'F', 
               task_states[p->state], p->hyp_events); 
        s = p->shared_info; 
        if( !is_idle_task(p) )
        {
            printk("Guest: events = %08lx, events_mask = %08lx\n", 
                   s->events, s->events_mask); 
            printk("Notifying guest...\n"); 
            cpu_mask |= mark_guest_event(p, _EVENT_DEBUG);
        }
    } while ( (p = p->next_task) != &idle0_task );

    read_unlock_irqrestore(&tasklist_lock, flags); 

    guest_event_notify(cpu_mask);
}

extern void perfc_printall (u_char key, void *dev_id, struct pt_regs *regs);
extern void perfc_reset (u_char key, void *dev_id, struct pt_regs *regs);
extern void dump_runq(u_char key, void *dev_id, struct pt_regs *regs);
extern void print_sched_histo(u_char key, void *dev_id, struct pt_regs *regs);
extern void reset_sched_histo(u_char key, void *dev_id, struct pt_regs *regs);
#ifndef NDEBUG
void reaudit_pages(u_char key, void *dev_id, struct pt_regs *regs);
void audit_all_pages(u_char key, void *dev_id, struct pt_regs *regs);
#endif


void initialize_keytable(void)
{
    int i; 

    /* first initialize key handler table */
    for ( i = 0; i < KEY_MAX; i++ ) 
	key_table[i].handler = (key_handler *)NULL; 
	
    /* setup own handlers */
    add_key_handler('d', dump_registers, "dump registers"); 
    add_key_handler('h', show_handlers, "show this message");
    add_key_handler('l', print_sched_histo, "print sched latency histogram");
    add_key_handler('L', reset_sched_histo, "reset sched latency histogram");
    add_key_handler('p', perfc_printall, "print performance counters"); 
    add_key_handler('P', perfc_reset,    "reset performance counters"); 
    add_key_handler('q', do_task_queues, "dump task queues + guest state");
    add_key_handler('r', dump_runq,      "dump run queues");
    add_key_handler('B', kill_dom0,      "reboot machine gracefully"); 
    add_key_handler('R', halt_machine,   "reboot machine ungracefully"); 
#ifndef NDEBUG
    add_key_handler('m', reaudit_pages, "re-audit pages");
    add_key_handler('M', audit_all_pages, "audit all pages");
#endif

    serial_set_rx_handler(sercon_handle, serial_rx);
}
