
/*
 * pervasive debugger
 * www.cl.cam.ac.uk/netos/pdb
 *
 * alex ho
 * 2004
 * university of cambridge computer laboratory
 *
 * code adapted originally from kgdb, nemesis, & gdbserver
 */

#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/regs.h>
#include <xen/keyhandler.h> 
#include <asm/apic.h>
#include <asm/domain_page.h>                           /* [un]map_domain_mem */
#include <asm/processor.h>
#include <asm/pdb.h>
#include <xen/list.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/init.h>

/* opt_pdb: Name of serial port for Xen pervasive debugger (and enable pdb) */
static unsigned char opt_pdb[10] = "none";
string_param("pdb", opt_pdb);

#define PDB_DEBUG_TRACE
#ifdef PDB_DEBUG_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

#define DEBUG_EXCEPTION     0x01
#define BREAKPT_EXCEPTION   0x03
#define PDB_LIVE_EXCEPTION  0x58
#define KEYPRESS_EXCEPTION  0x88

#define BUFMAX 400

static const char hexchars[] = "0123456789abcdef";

static int remote_debug;

#define PDB_BUFMAX 1024
static char pdb_in_buffer[PDB_BUFMAX];
static char pdb_out_buffer[PDB_BUFMAX];
static char pdb_buffer[PDB_BUFMAX];

struct pdb_context pdb_ctx;
int pdb_continue_thread = 0;
int pdb_general_thread = 0;

void pdb_put_packet (unsigned char *buffer, int ack);
void pdb_bkpt_check (u_char *buffer, int length,
		     unsigned long cr3, unsigned long addr);

int pdb_initialized = 0;
int pdb_page_fault_possible = 0;
int pdb_page_fault_scratch = 0;                     /* just a handy variable */
int pdb_page_fault = 0;
static int pdb_serhnd = -1;
static int pdb_stepping = 0;

int pdb_system_call = 0;
unsigned char pdb_system_call_enter_instr = 0;       /* original enter instr */
unsigned char pdb_system_call_leave_instr = 0;        /* original next instr */
unsigned long pdb_system_call_next_addr = 0;         /* instr after int 0x80 */
unsigned long pdb_system_call_eflags_addr = 0;      /* saved eflags on stack */

static inline void pdb_put_char(unsigned char c)
{
    serial_putc(pdb_serhnd, c);
}

static inline unsigned char pdb_get_char(void)
{
    return serial_getc(pdb_serhnd);
}

int
get_char (char *addr)
{
    return *addr;
}

void
set_char (char *addr, int val)
{
    *addr = val;
}

void
pdb_process_query (char *ptr)
{
    if (strcmp(ptr, "C") == 0)
    {
        /* empty string */
    }
    else if (strcmp(ptr, "fThreadInfo") == 0)
    {
#ifdef PDB_PAST
        struct domain *p;
#endif /* PDB_PAST */

        int buf_idx = 0;

	pdb_out_buffer[buf_idx++] = 'l';
	pdb_out_buffer[buf_idx++] = 0;

#ifdef PDB_PAST
	switch (pdb_level)
	{
	case PDB_LVL_XEN:                        /* return a list of domains */
	{
	    int count = 0;

	    read_lock(&domlist_lock);

	    pdb_out_buffer[buf_idx++] = 'm';
	    for_each_domain ( p )
	    {
	        domid_t domain = p->domain + PDB_ID_OFFSET;

		if (count > 0)
		{
		    pdb_out_buffer[buf_idx++] = ',';
		}
		if (domain > 15)
		{
		    pdb_out_buffer[buf_idx++] = hexchars[domain >> 4];
		}
		pdb_out_buffer[buf_idx++] = hexchars[domain % 16];
		count++;
	    }
	    pdb_out_buffer[buf_idx++] = 0;

	    read_unlock(&domlist_lock);
	    break;
	}
	case PDB_LVL_GUESTOS:                  /* return a list of processes */
	{
	    int foobar[20];
	    int loop, total;

                                                       /* this cr3 is wrong! */
	    total = pdb_linux_process_list(pdb_ctx[pdb_level].info_cr3,
					   foobar, 20);

	    pdb_out_buffer[buf_idx++] = 'm';     
	    pdb_out_buffer[buf_idx++] = '1';              /* 1 is to go back */
	    for (loop = 0; loop < total; loop++)
	    {
	        int pid = foobar[loop] + PDB_ID_OFFSET;

		pdb_out_buffer[buf_idx++] = ',';
		if (pid > 15)
		{
		    pdb_out_buffer[buf_idx++] = hexchars[pid >> 4];
		}
		pdb_out_buffer[buf_idx++] = hexchars[pid % 16];
	    }
	    pdb_out_buffer[buf_idx++] = 0;
	    break;
	}
	case PDB_LVL_PROCESS:                                     /* hmmm... */
	{
	    pdb_out_buffer[buf_idx++] = 'm';
	    pdb_out_buffer[buf_idx++] = '1';              /* 1 is to go back */
	    break;
	}
	default:
	    break;
	}
#endif /* PDB_PAST */

    }
    else if (strcmp(ptr, "sThreadInfo") == 0)
    {
        int buf_idx = 0;

	pdb_out_buffer[buf_idx++] = 'l';
	pdb_out_buffer[buf_idx++] = 0;
    }
    else if (strncmp(ptr, "ThreadExtraInfo,", 16) == 0)
    {
        int thread = 0;
	char *message = "foobar ?";

	ptr += 16;
        if (hexToInt (&ptr, &thread))
	{
            mem2hex (message, pdb_out_buffer, strlen(message) + 1);
	}

#ifdef PDB_PAST
        int thread = 0;
	char message[16];
	struct domain *p;

	strncpy (message, dom0->name, 16);

	ptr += 16;
        if (hexToInt (&ptr, &thread))
	{
            mem2hex ((char *)message, pdb_out_buffer, strlen(message) + 1);
	}
#endif /* PDB_PAST */

#ifdef PDB_FUTURE
      {
	char string[task_struct_comm_length];

	string[0] = 0;
	pdb_linux_process_details (cr3, pid, string);
	printk (" (%s)", string);
      }
#endif /* PDB_FUTURE*/

    }
    else if (strcmp(ptr, "Offsets") == 0)
    {
        /* empty string */
    }
    else if (strncmp(ptr, "Symbol", 6) == 0)
    {
        strcpy (pdb_out_buffer, "OK");
    }
    else
    {
        printk("pdb: error, unknown query [%s]\n", ptr);
    }
}

void
pdb_x86_to_gdb_regs (char *buffer, struct xen_regs *regs)
{
    int idx = 0;

    mem2hex ((char *)&regs->eax, &buffer[idx], sizeof(regs->eax));
    idx += sizeof(regs->eax) * 2;
    mem2hex ((char *)&regs->ecx, &buffer[idx], sizeof(regs->ecx));
    idx += sizeof(regs->ecx) * 2;
    mem2hex ((char *)&regs->edx, &buffer[idx], sizeof(regs->edx));
    idx += sizeof(regs->edx) * 2;
    mem2hex ((char *)&regs->ebx, &buffer[idx], sizeof(regs->ebx));
    idx += sizeof(regs->ebx) * 2;
    mem2hex ((char *)&regs->esp, &buffer[idx], sizeof(regs->esp));
    idx += sizeof(regs->esp) * 2;
    mem2hex ((char *)&regs->ebp, &buffer[idx], sizeof(regs->ebp));
    idx += sizeof(regs->ebp) * 2;
    mem2hex ((char *)&regs->esi, &buffer[idx], sizeof(regs->esi));
    idx += sizeof(regs->esi) * 2;
    mem2hex ((char *)&regs->edi, &buffer[idx], sizeof(regs->edi));
    idx += sizeof(regs->edi) * 2;
    mem2hex ((char *)&regs->eip, &buffer[idx], sizeof(regs->eip));
    idx += sizeof(regs->eip) * 2;
    mem2hex ((char *)&regs->eflags, &buffer[idx], sizeof(regs->eflags));
    idx += sizeof(regs->eflags) * 2;
    mem2hex ((char *)&regs->cs, &buffer[idx], sizeof(regs->cs));
    idx += sizeof(regs->cs) * 2;
    mem2hex ((char *)&regs->ss, &buffer[idx], sizeof(regs->ss));
    idx += sizeof(regs->ss) * 2;
    mem2hex ((char *)&regs->ds, &buffer[idx], sizeof(regs->ds));
    idx += sizeof(regs->ds) * 2;
    mem2hex ((char *)&regs->es, &buffer[idx], sizeof(regs->es));
    idx += sizeof(regs->es) * 2;
    mem2hex ((char *)&regs->fs, &buffer[idx], sizeof(regs->fs));
    idx += sizeof(regs->fs) * 2;
    mem2hex ((char *)&regs->gs, &buffer[idx], sizeof(regs->gs));
}

/* at this point we allow any register to be changed, caveat emptor */
void
pdb_gdb_to_x86_regs (struct xen_regs *regs, char *buffer)
{
    hex2mem(buffer, (char *)&regs->eax, sizeof(regs->eax));
    buffer += sizeof(regs->eax) * 2;
    hex2mem(buffer, (char *)&regs->ecx, sizeof(regs->ecx));
    buffer += sizeof(regs->ecx) * 2;
    hex2mem(buffer, (char *)&regs->edx, sizeof(regs->edx));
    buffer += sizeof(regs->edx) * 2;
    hex2mem(buffer, (char *)&regs->ebx, sizeof(regs->ebx));
    buffer += sizeof(regs->ebx) * 2;
    hex2mem(buffer, (char *)&regs->esp, sizeof(regs->esp));
    buffer += sizeof(regs->esp) * 2;
    hex2mem(buffer, (char *)&regs->ebp, sizeof(regs->ebp));
    buffer += sizeof(regs->ebp) * 2;
    hex2mem(buffer, (char *)&regs->esi, sizeof(regs->esi));
    buffer += sizeof(regs->esi) * 2;
    hex2mem(buffer, (char *)&regs->edi, sizeof(regs->edi));
    buffer += sizeof(regs->edi) * 2;
    hex2mem(buffer, (char *)&regs->eip, sizeof(regs->eip));
    buffer += sizeof(regs->eip) * 2;
    hex2mem(buffer, (char *)&regs->eflags, sizeof(regs->eflags));
    buffer += sizeof(regs->eflags) * 2;
    hex2mem(buffer, (char *)&regs->cs, sizeof(regs->cs));
    buffer += sizeof(regs->cs) * 2;
    hex2mem(buffer, (char *)&regs->ss, sizeof(regs->ss));
    buffer += sizeof(regs->ss) * 2;
    hex2mem(buffer, (char *)&regs->ds, sizeof(regs->ds));
    buffer += sizeof(regs->ds) * 2;
    hex2mem(buffer, (char *)&regs->es, sizeof(regs->es));
    buffer += sizeof(regs->es) * 2;
    hex2mem(buffer, (char *)&regs->fs, sizeof(regs->fs));
    buffer += sizeof(regs->fs) * 2;
    hex2mem(buffer, (char *)&regs->gs, sizeof(regs->gs));
}

int
pdb_process_command (char *ptr, struct xen_regs *regs, unsigned long cr3,
		     int sigval)
{
    int length;
    unsigned long addr;
    int ack = 1;                           /* wait for ack in pdb_put_packet */
    int go = 0;

    TRC(printf("pdb: [%s]\n", ptr));

    pdb_out_buffer[0] = 0;

    if (pdb_ctx.valid == 1)
    {
        if (pdb_ctx.domain == -1)                        /* pdb context: xen */
	{
	    struct domain *p;

	    p = &idle0_task;
	    if (p->mm.shadow_mode)
	        pdb_ctx.ptbr = pagetable_val(p->mm.shadow_table);
	    else
	        pdb_ctx.ptbr = pagetable_val(p->mm.pagetable);
	}
	else if (pdb_ctx.process == -1)             /* pdb context: guest os */
	{
	    struct domain *p;

	    if (pdb_ctx.domain == -2)
	    {
	        p = find_last_domain();
	    }
	    else
	    {
	        p = find_domain_by_id(pdb_ctx.domain);
	    }
	    if (p == NULL)
	    {
	        printk ("pdb error: unknown domain [0x%x]\n", pdb_ctx.domain);
	        strcpy (pdb_out_buffer, "E01");
		pdb_ctx.domain = -1;
		goto exit;
	    }
	    if (p->mm.shadow_mode)
	        pdb_ctx.ptbr = pagetable_val(p->mm.shadow_table);
	    else
	        pdb_ctx.ptbr = pagetable_val(p->mm.pagetable);
	    put_domain(p);
	}
	else                                         /* pdb context: process */
	{
	    struct domain *p;
	    unsigned long domain_ptbr;

	    p = find_domain_by_id(pdb_ctx.domain);
	    if (p == NULL)
	    {
	        printk ("pdb error: unknown domain [0x%x][0x%x]\n", 
			pdb_ctx.domain, pdb_ctx.process);
	        strcpy (pdb_out_buffer, "E01");
		pdb_ctx.domain = -1;
		goto exit;
	    }
	    if (p->mm.shadow_mode)
	        domain_ptbr = pagetable_val(p->mm.shadow_table);
	    else
	        domain_ptbr = pagetable_val(p->mm.pagetable);
	    put_domain(p);

	    pdb_ctx.ptbr = domain_ptbr;
	    /*pdb_ctx.ptbr=pdb_linux_pid_ptbr(domain_ptbr, pdb_ctx.process);*/
	}

	pdb_ctx.valid = 0;
	TRC(printk ("pdb change context (dom:%d, proc:%d) now 0x%lx\n",
		    pdb_ctx.domain, pdb_ctx.process, pdb_ctx.ptbr));
    }

    switch (*ptr++)
    {
    case '?':
        pdb_out_buffer[0] = 'S';
        pdb_out_buffer[1] = hexchars[sigval >> 4];
        pdb_out_buffer[2] = hexchars[sigval % 16];
        pdb_out_buffer[3] = 0;
        break;
    case 'S':                                            /* step with signal */
    case 's':                                                        /* step */
    {
        if ( pdb_system_call_eflags_addr != 0 )
	{
	    unsigned long eflags;
	    char eflags_buf[sizeof(eflags)*2];       /* STUPID STUPID STUPID */

	    pdb_linux_get_values((u_char*)&eflags, sizeof(eflags), 
				 pdb_system_call_eflags_addr, 
				 pdb_ctx.process, pdb_ctx.ptbr);
	    eflags |= X86_EFLAGS_TF;
	    mem2hex ((u_char *)&eflags, eflags_buf, sizeof(eflags)); 
	    pdb_linux_set_values(eflags_buf, sizeof(eflags),
				 pdb_system_call_eflags_addr,
				 pdb_ctx.process, pdb_ctx.ptbr);
	}

        regs->eflags |= X86_EFLAGS_TF;
        pdb_stepping = 1;
        return 1;                                        
        /* not reached */
    }
    case 'C':                                        /* continue with signal */
    case 'c':                                                    /* continue */
    {
        if ( pdb_system_call_eflags_addr != 0 )
	{
	    unsigned long eflags;
	    char eflags_buf[sizeof(eflags)*2];       /* STUPID STUPID STUPID */

	    pdb_linux_get_values((u_char*)&eflags, sizeof(eflags), 
				 pdb_system_call_eflags_addr, 
				 pdb_ctx.process, pdb_ctx.ptbr);
	    eflags &= ~X86_EFLAGS_TF;
	    mem2hex ((u_char *)&eflags, eflags_buf, sizeof(eflags)); 
	    pdb_linux_set_values(eflags_buf, sizeof(eflags),
				 pdb_system_call_eflags_addr,
				 pdb_ctx.process, pdb_ctx.ptbr);
	}

        regs->eflags &= ~X86_EFLAGS_TF;
        return 1;                         /* jump out before replying to gdb */
        /* not reached */
    }
    case 'd':
        remote_debug = !(remote_debug);                 /* toggle debug flag */
        break;
    case 'D':                                                      /* detach */
        return go;
        /* not reached */
    case 'g':                       /* return the value of the CPU registers */
    {
        pdb_x86_to_gdb_regs (pdb_out_buffer, regs);
        break;
    }
    case 'G':              /* set the value of the CPU registers - return OK */
    {
        pdb_gdb_to_x86_regs (regs, ptr);
        break;
    }
    case 'H':
    {
        int thread;
        char *next = &ptr[1];

        if (hexToInt (&next, &thread))
        {
            if (*ptr == 'c')
            {
	        pdb_continue_thread = thread;
            }
            else if (*ptr == 'g')
            {
	        pdb_general_thread = thread;
            }
            else
            {
                printk ("pdb error: unknown set thread command %c (%d)\n", 
                        *ptr, thread);
		strcpy (pdb_out_buffer, "E00");
		break;
            }
        }
        strcpy (pdb_out_buffer, "OK");
        break;
    }
    case 'k':                                                /* kill request */
    {
        strcpy (pdb_out_buffer, "OK");                        /* ack for fun */
        printk ("don't kill bill...\n");
        ack = 0;
        break;
    }

    case 'q':
    {
        pdb_process_query(ptr);
        break;
    }

    /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
    case 'm':
    {
        /* TRY TO READ %x,%x.  IF SUCCEED, SET PTR = 0 */
        if (hexToInt (&ptr, (int *)&addr))
            if (*(ptr++) == ',')
                if (hexToInt (&ptr, &length))
                {
                    ptr = 0;

		    pdb_page_fault_possible = 1;
		    pdb_page_fault = 0;
		    if (addr >= PAGE_OFFSET)
		    {
                        mem2hex ((char *) addr, pdb_out_buffer, length); 
		    }
		    else if (pdb_ctx.process != -1)
		    {
		        pdb_linux_get_values(pdb_buffer, length, addr, 
					     pdb_ctx.process, pdb_ctx.ptbr);
                        mem2hex (pdb_buffer, pdb_out_buffer, length); 
		    }
                    else
                    {
		        pdb_get_values (pdb_buffer, length, 
					pdb_ctx.ptbr, addr);
                        mem2hex (pdb_buffer, pdb_out_buffer, length);
                    }

		    pdb_page_fault_possible = 0;
		    if (pdb_page_fault)
		    {
                        strcpy (pdb_out_buffer, "E03");
		    }
                }
	    
        if (ptr)
        {
            strcpy (pdb_out_buffer, "E01");
        }
        break;
    }

    /* MAA..AA,LLLL: Write LLLL bytes at address AA.AA return OK */
    case 'M':
    {
        /* TRY TO READ '%x,%x:'.  IF SUCCEED, SET PTR = 0 */
        if (hexToInt (&ptr, (int *)&addr))
            if (*(ptr++) == ',')
                if (hexToInt (&ptr, &length))
                    if (*(ptr++) == ':')
                    {

		        pdb_page_fault_possible = 1;
			pdb_page_fault = 0;
			if (addr >= PAGE_OFFSET)
			{
			    hex2mem (ptr, (char *)addr, length);
			    pdb_bkpt_check(ptr, length, pdb_ctx.ptbr, addr);
			}
			else if (pdb_ctx.process != -1)
			{
			    pdb_linux_set_values(ptr, length, addr,
						 pdb_ctx.process, 
						 pdb_ctx.ptbr);
			    pdb_bkpt_check(ptr, length, pdb_ctx.ptbr, addr);
			}
			else
			{
			    pdb_set_values (ptr, length,
					    pdb_ctx.ptbr, addr);
			    pdb_bkpt_check(ptr, length, pdb_ctx.ptbr, addr);
			}
			pdb_page_fault_possible = 0;
                        if (pdb_page_fault)
                        {
                            strcpy (pdb_out_buffer, "E03");
                        }
                        else
                        {
                            strcpy (pdb_out_buffer, "OK");
                        }

                        ptr = 0;
                    }
        if (ptr)
        {
            strcpy (pdb_out_buffer, "E02");
        }
        break;
    }
    case 'T':
    {
        int id;

        if (hexToInt (&ptr, &id))
        {
	    strcpy (pdb_out_buffer, "E00");

#ifdef PDB_PAST

	    switch (pdb_level)                             /* previous level */
	    {
	        case PDB_LVL_XEN:
		{
		    struct domain *p;
		    id -= PDB_ID_OFFSET;
		    if ( (p = find_domain_by_id(id)) == NULL)
		        strcpy (pdb_out_buffer, "E00");
		    else
		        strcpy (pdb_out_buffer, "OK");
		    put_domain(p);

		    pdb_level = PDB_LVL_GUESTOS;
		    pdb_ctx[pdb_level].ctrl = id;
		    pdb_ctx[pdb_level].info = id;
		    break;
		}
	        case PDB_LVL_GUESTOS:
		{
		    if (pdb_level == -1)
		    {
		        pdb_level = PDB_LVL_XEN;
		    }
		    else
		    {
		        pdb_level = PDB_LVL_PROCESS;
			pdb_ctx[pdb_level].ctrl = id;
			pdb_ctx[pdb_level].info = id;
		    }
		    break;
		}
	        case PDB_LVL_PROCESS:
		{
		    if (pdb_level == -1)
		    {
		        pdb_level = PDB_LVL_GUESTOS;
		    }
		    break;
		}
	        default:
		{
		    printk ("pdb internal error: invalid level [%d]\n", 
			    pdb_level);
		}
	    }

#endif /* PDB_PAST */
        }
        break;
    }
    }

exit:
    /* reply to the request */
    pdb_put_packet (pdb_out_buffer, ack);

    return go;
}

/*
 * process an input character from the serial line.
 *
 * return "1" if the character is a gdb debug string
 * (and hence shouldn't be further processed).
 */

int pdb_debug_state = 0;                /* small parser state machine */

int hex(char ch)
{
    if ((ch >= 'a') && (ch <= 'f')) return (ch-'a'+10);
    if ((ch >= '0') && (ch <= '9')) return (ch-'0');
    if ((ch >= 'A') && (ch <= 'F')) return (ch-'A'+10);
    return (-1);
}

/* convert the memory pointed to by mem into hex, placing result in buf */
/* return a pointer to the last char put in buf (null) */
char *
mem2hex (mem, buf, count)
    char *mem;
    char *buf;
    int count;
{
    int i;
    unsigned char ch;

    for (i = 0; i < count; i++)
    {
        ch = get_char (mem++);
        *buf++ = hexchars[ch >> 4];
        *buf++ = hexchars[ch % 16];
    }
    *buf = 0;
    return (buf);
}

/* convert the hex array pointed to by buf into binary to be placed in mem */
/* return a pointer to the character AFTER the last byte written */
char *
hex2mem (buf, mem, count)
    char *buf;
    char *mem;
    int count;
{
    int i;
    unsigned char ch;

    for (i = 0; i < count; i++)
    {
        ch = hex (*buf++) << 4;
        ch = ch + hex (*buf++);
        set_char (mem++, ch);
    }
    return (mem);
}

int
hexToInt (char **ptr, int *intValue)
{
    int numChars = 0;
    int hexValue;
    int negative = 0;

    *intValue = 0;

    if (**ptr == '-')
    {
        negative = 1;
        numChars++;
        (*ptr)++;
    }

    while (**ptr)
    {
        hexValue = hex (**ptr);
        if (hexValue >= 0)
        {
            *intValue = (*intValue << 4) | hexValue;
            numChars++;
        }
        else
            break;

        (*ptr)++;
    }

    if ( negative )
        *intValue *= -1;
  
    return (numChars);
}

/***********************************************************************/
/***********************************************************************/


/*
 * Add a breakpoint to the list of known breakpoints.
 * For now there should only be two or three breakpoints so
 * we use a simple linked list.  In the future, maybe a red-black tree?
 */
struct pdb_breakpoint breakpoints;

void pdb_bkpt_add (unsigned long cr3, unsigned long address)
{
    struct pdb_breakpoint *bkpt = xmalloc(sizeof(*bkpt));
    bkpt->cr3 = cr3;
    bkpt->address = address;
    list_add(&bkpt->list, &breakpoints.list);
}

/*
 * Check to see of the breakpoint is in the list of known breakpoints 
 * Return 1 if it has been set, NULL otherwise.
 */
struct pdb_breakpoint* pdb_bkpt_search (unsigned long cr3, 
					unsigned long address)
{
    struct list_head *list_entry;
    struct pdb_breakpoint *bkpt;

    list_for_each(list_entry, &breakpoints.list)
    {
        bkpt = list_entry(list_entry, struct pdb_breakpoint, list);
	if ( bkpt->cr3 == cr3 && bkpt->address == address )
            return bkpt;
    }

    return NULL;
}

/*
 * Remove a breakpoint to the list of known breakpoints.
 * Return 1 if the element was not found, otherwise 0.
 */
int pdb_bkpt_remove (unsigned long cr3, unsigned long address)
{
    struct list_head *list_entry;
    struct pdb_breakpoint *bkpt;

    list_for_each(list_entry, &breakpoints.list)
    {
        bkpt = list_entry(list_entry, struct pdb_breakpoint, list);
	if ( bkpt->cr3 == cr3 && bkpt->address == address )
	{
            list_del(&bkpt->list);
            xfree(bkpt);
            return 0;
	}
    }

    return 1;
}

/*
 * Check to see if a memory write is really gdb setting a breakpoint
 */
void pdb_bkpt_check (u_char *buffer, int length,
		     unsigned long cr3, unsigned long addr)
{
    if (length == 1 && buffer[0] == 'c' && buffer[1] == 'c')
    {
        /* inserting a new breakpoint */
        pdb_bkpt_add(cr3, addr);
        TRC(printk("pdb breakpoint detected at 0x%lx:0x%lx\n", cr3, addr));
    }
    else if ( pdb_bkpt_remove(cr3, addr) == 0 )
    {
        /* removing a breakpoint */
        TRC(printk("pdb breakpoint cleared at 0x%lx:0x%lx\n", cr3, addr));
    }
}

/***********************************************************************/

int pdb_change_values(u_char *buffer, int length,
		      unsigned long cr3, unsigned long addr, int rw);
int pdb_change_values_one_page(u_char *buffer, int length,
			       unsigned long cr3, unsigned long addr, int rw);

#define __PDB_GET_VAL 1
#define __PDB_SET_VAL 2

/*
 * Set memory in a domain's address space
 * Set "length" bytes at "address" from "domain" to the values in "buffer".
 * Return the number of bytes set, 0 if there was a problem.
 */

int pdb_set_values(u_char *buffer, int length,
		   unsigned long cr3, unsigned long addr)
{
    int count = pdb_change_values(buffer, length, cr3, addr, __PDB_SET_VAL);
    return count;
}

/*
 * Read memory from a domain's address space.
 * Fetch "length" bytes at "address" from "domain" into "buffer".
 * Return the number of bytes read, 0 if there was a problem.
 */

int pdb_get_values(u_char *buffer, int length,
		   unsigned long cr3, unsigned long addr)
{
  return pdb_change_values(buffer, length, cr3, addr, __PDB_GET_VAL);
}

/*
 * Read or write memory in an address space
 */
int pdb_change_values(u_char *buffer, int length,
		      unsigned long cr3, unsigned long addr, int rw)
{
    int remaining;                /* number of bytes to touch past this page */
    int bytes = 0;

    while ( (remaining = (addr + length - 1) - (addr | (PAGE_SIZE - 1))) > 0)
    {
        bytes += pdb_change_values_one_page(buffer, length - remaining, 
					    cr3, addr, rw);
	buffer = buffer + (2 * (length - remaining));
	length = remaining;
	addr = (addr | (PAGE_SIZE - 1)) + 1;
    }

    bytes += pdb_change_values_one_page(buffer, length, cr3, addr, rw);
    return bytes;
}

/*
 * Change memory in a process' address space in one page
 * Read or write "length" bytes at "address" into/from "buffer"
 * from the virtual address space referenced by "cr3".
 * Return the number of bytes read, 0 if there was a problem.
 */

int pdb_change_values_one_page(u_char *buffer, int length,
			       unsigned long cr3, unsigned long addr, int rw)
{
    l2_pgentry_t* l2_table = NULL;                         /* page directory */
    l1_pgentry_t* l1_table = NULL;                             /* page table */
    u_char *page;                                                 /* 4k page */
    int bytes = 0;

    l2_table = map_domain_mem(cr3); 
    l2_table += l2_table_offset(addr);
    if (!(l2_pgentry_val(*l2_table) & _PAGE_PRESENT)) 
    {
	if (pdb_page_fault_possible == 1)
	{
	    pdb_page_fault = 1;
	    TRC(printk("pdb: L2 error (0x%lx)\n", addr));
	}
	else
	{
	    printk ("pdb error: cr3: 0x%lx    dom0cr3:  0x%lx\n",  cr3,
		    dom0->mm.shadow_mode ? pagetable_val(dom0->mm.shadow_table)
		    : pagetable_val(dom0->mm.pagetable));
	    printk ("pdb error: L2:0x%p (0x%lx)\n", 
		    l2_table, l2_pgentry_val(*l2_table));
	}
	goto exit2;
    }

    if (l2_pgentry_val(*l2_table) & _PAGE_PSE)
    {
#define PSE_PAGE_SHIFT           L2_PAGETABLE_SHIFT
#define PSE_PAGE_SIZE	         (1UL << PSE_PAGE_SHIFT)
#define PSE_PAGE_MASK	         (~(PSE_PAGE_SIZE-1))

#define L1_PAGE_BITS ( (ENTRIES_PER_L1_PAGETABLE - 1) << L1_PAGETABLE_SHIFT )

#define pse_pgentry_to_phys(_x) (l2_pgentry_val(_x) & PSE_PAGE_MASK)

        page = map_domain_mem(pse_pgentry_to_phys(*l2_table) +    /* 10 bits */
			      (addr & L1_PAGE_BITS));             /* 10 bits */
	page += addr & (PAGE_SIZE - 1);                           /* 12 bits */
    }
    else
    {
        l1_table = map_domain_mem(l2_pgentry_to_phys(*l2_table));
	l1_table += l1_table_offset(addr); 
	if (!(l1_pgentry_val(*l1_table) & _PAGE_PRESENT))
	{
	    if (pdb_page_fault_possible == 1)
	    {
	        pdb_page_fault = 1;
		TRC(printk ("pdb: L1 error (0x%lx)\n", addr));
	    }
	    else
	    {
	        printk ("L2:0x%p (0x%lx) L1:0x%p (0x%lx)\n", 
			l2_table, l2_pgentry_val(*l2_table),
			l1_table, l1_pgentry_val(*l1_table));
	    }
	    goto exit1;
	}

	page = map_domain_mem(l1_pgentry_to_phys(*l1_table));
	page += addr & (PAGE_SIZE - 1);
    }

    switch (rw)
    {
    case __PDB_GET_VAL:                                              /* read */
        memcpy (buffer, page, length);
	bytes = length;
	break;
    case __PDB_SET_VAL:                                             /* write */
        hex2mem (buffer, page, length);
	bytes = length;
	break;
    default:                                                      /* unknown */
        printk ("error: unknown RW flag: %d\n", rw);
	return 0;
    }

    unmap_domain_mem((void *)page); 
exit1:
    if (l1_table != NULL)
        unmap_domain_mem((void *)l1_table);
exit2:
    unmap_domain_mem((void *)l2_table);

    return bytes;
}

/***********************************************************************/

void breakpoint(void);

/* send the packet in buffer.  */
void pdb_put_packet (unsigned char *buffer, int ack)
{
    unsigned char checksum;
    int count;
    char ch;
    
    /*  $<packet info>#<checksum> */
    /*  do */
    {
        pdb_put_char ('$');
	checksum = 0;
	count = 0;

	while ((ch = buffer[count]))
	{
            pdb_put_char (ch);
	    checksum += ch;
	    count += 1;
        }

	pdb_put_char('#');
	pdb_put_char(hexchars[checksum >> 4]);
	pdb_put_char(hexchars[checksum % 16]);
    }

    if (ack)
    {
	if ((ch = pdb_get_char()) != '+')
	{
	    printk(" pdb return error: %c 0x%x [%s]\n", ch, ch, buffer);
	}
    }
}

void pdb_get_packet(char *buffer)
{
    int count;
    char ch;
    unsigned char checksum = 0;
    unsigned char xmitcsum = 0;

    do
    {
        while ((ch = pdb_get_char()) != '$');

	count = 0;
	checksum = 0;

	while (count < BUFMAX)
	{
	    ch = pdb_get_char();
	    if (ch  == '#') break;
	    checksum += ch;
	    buffer[count] = ch;
	    count++;
	}
	buffer[count] = 0;

	if (ch == '#')
	{
	    xmitcsum = hex(pdb_get_char()) << 4;
	    xmitcsum += hex(pdb_get_char());

	    if (xmitcsum == checksum)
	    {
	        pdb_put_char('+');
		if (buffer[2] == ':')
		{
		    printk ("pdb: obsolete gdb packet (sequence ID)\n");
		}
	    }
	    else
	    {
	        pdb_put_char('-');
	    }
	}
    } while (checksum != xmitcsum);

    return;
}

/*
 * process a machine interrupt or exception
 * Return 1 if pdb is not interested in the exception; it should
 * be propagated to the guest os.
 */

int pdb_handle_exception(int exceptionVector,
			 struct xen_regs *xen_regs)
{
    int signal = 0;
    struct pdb_breakpoint* bkpt;
    int watchdog_save;
    unsigned long cr3 = read_cr3();

    /* No vm86 handling here as yet. */
    if ( VM86_MODE(xen_regs) )
        return 1;

    /* If the exception is an int3 from user space then pdb is only
       interested if it re-wrote an instruction set the breakpoint.
       This occurs when leaving a system call from a domain.
    */
    if ( (exceptionVector == 3) &&
	 RING_3(xen_regs) && 
	 (xen_regs->eip != (pdb_system_call_next_addr + 1)) )
    {
        TRC(printf("pdb: user bkpt (0x%x) at 0x%x:0x%lx:0x%x\n", 
		   exceptionVector, xen_regs->cs & 3, cr3, xen_regs->eip));
	return 1;
    }

    /*
     * If PDB didn't set the breakpoint, is not single stepping, 
     * is not entering a system call in a domain,
     * the user didn't press the magic debug key, 
     * then we don't handle the exception.
     */
    bkpt = pdb_bkpt_search(cr3, xen_regs->eip - 1);
    if ( (bkpt == NULL) &&
         !pdb_stepping && 
	 !pdb_system_call &&
	 xen_regs->eip != pdb_system_call_next_addr + 1 &&
	 (exceptionVector != KEYPRESS_EXCEPTION) &&
	 xen_regs->eip < 0xc0000000)  /* Linux-specific for now! */
    {
        TRC(printf("pdb: user bkpt (0x%x) at 0x%lx:0x%x\n", 
		   exceptionVector, cr3, xen_regs->eip));
	return 1;
    }

    printk("pdb_handle_exception [0x%x][0x%lx:0x%x]\n",
	   exceptionVector, cr3, xen_regs->eip);

    if ( pdb_stepping )
    {
        /* Stepped one instruction; now return to normal execution. */
        xen_regs->eflags &= ~X86_EFLAGS_TF;
        pdb_stepping = 0;
    }

    if ( pdb_system_call )
    {
	pdb_system_call = 0;

	pdb_linux_syscall_exit_bkpt (xen_regs, &pdb_ctx);

	/* we don't have a saved breakpoint so we need to rewind eip */
	xen_regs->eip--;
	
	/* if ther user doesn't care about breaking when entering a
	   system call then we'll just ignore the exception */
	if ( (pdb_ctx.system_call & 0x01) == 0 )
	{
	    return 0;
	}
    }

    if ( exceptionVector == BREAKPT_EXCEPTION && bkpt != NULL)
    {
        /* Executed Int3: replace breakpoint byte with real program byte. */
        xen_regs->eip--;
    }

    /* returning to user space after a system call */
    if ( xen_regs->eip == pdb_system_call_next_addr + 1)
    {
        u_char instr[2];                      /* REALLY REALLY REALLY STUPID */

	mem2hex (&pdb_system_call_leave_instr, instr, sizeof(instr)); 

	pdb_linux_set_values (instr, 1, pdb_system_call_next_addr,
			      pdb_ctx.process, pdb_ctx.ptbr);

	pdb_system_call_next_addr = 0;
	pdb_system_call_leave_instr = 0;

	/* manually rewind eip */
	xen_regs->eip--;

	/* if the user doesn't care about breaking when returning 
	   to user space after a system call then we'll just ignore 
	   the exception */
	if ( (pdb_ctx.system_call & 0x02) == 0 )
	{
	    return 0;
	}
    }

    /* Generate a signal for GDB. */
    switch ( exceptionVector )
    {
    case KEYPRESS_EXCEPTION:
        signal = 2; break;                                  /* SIGINT */
    case DEBUG_EXCEPTION:
        signal = 5; break;                                 /* SIGTRAP */
    case BREAKPT_EXCEPTION: 
        signal = 5; break;                                 /* SIGTRAP */
    default:
        printk("pdb: can't generate signal for unknown exception vector %d\n",
               exceptionVector);
        break;
    }

    pdb_out_buffer[0] = 'S';
    pdb_out_buffer[1] = hexchars[signal >> 4];
    pdb_out_buffer[2] = hexchars[signal % 16];
    pdb_out_buffer[3] = 0;
    pdb_put_packet(pdb_out_buffer, 1);

    watchdog_save = watchdog_on;
    watchdog_on = 0;

    do {
        pdb_out_buffer[0] = 0;
	pdb_get_packet(pdb_in_buffer);
    }
    while ( pdb_process_command(pdb_in_buffer, xen_regs, cr3, signal) == 0 );

    watchdog_on = watchdog_save;

    return 0;
}

void pdb_key_pressed(unsigned char key)
{
    struct xen_regs *regs = (struct xen_regs *)get_execution_context();
    pdb_handle_exception(KEYPRESS_EXCEPTION, regs);
}

void pdb_handle_debug_trap(struct xen_regs *regs, long error_code)
{
    unsigned int condition;
    struct domain *d = current;
    struct trap_bounce *tb = &d->thread.trap_bounce;

    __asm__ __volatile__("movl %%db6,%0" : "=r" (condition));
    if ( (condition & (1 << 14)) != (1 << 14) )
        printk("\nwarning: debug trap w/o BS bit [0x%x]\n\n", condition);
    __asm__("movl %0,%%db6" : : "r" (0));

    if ( pdb_handle_exception(1, regs) != 0 )
    {
        d->thread.debugreg[6] = condition;

        tb->flags = TBF_EXCEPTION;
        tb->cs    = d->thread.traps[1].cs;
        tb->eip   = d->thread.traps[1].address;
    }
}

void initialize_pdb()
{
    /* Certain state must be initialised even when PDB will not be used. */
    memset((void *) &breakpoints, 0, sizeof(breakpoints));
    INIT_LIST_HEAD(&breakpoints.list);
    pdb_stepping = 0;

    if ( strcmp(opt_pdb, "none") == 0 )
        return;

    if ( (pdb_serhnd = parse_serial_handle(opt_pdb)) == -1 )
    {
        printk("error: failed to initialize PDB on port %s\n", opt_pdb);
        return;
    }

    pdb_ctx.valid = 1;
    pdb_ctx.domain = -1;
    pdb_ctx.process = -1;
    pdb_ctx.system_call = 0;
    pdb_ctx.ptbr = 0;

    printk("pdb: pervasive debugger (%s)   www.cl.cam.ac.uk/netos/pdb\n", 
	   opt_pdb);

    /* Acknowledge any spurious GDB packets. */
    pdb_put_char('+');

    register_keyhandler('D', pdb_key_pressed, "enter pervasive debugger");

    pdb_initialized = 1;
}

void breakpoint(void)
{
    if ( pdb_initialized )
        asm("int $3");
}
