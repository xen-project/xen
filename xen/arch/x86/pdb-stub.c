
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
#include <asm/ptrace.h>
#include <xen/keyhandler.h> 
#include <asm/apic.h>
#include <asm/domain_page.h>                           /* [un]map_domain_mem */
#include <asm/processor.h>
#include <asm/pdb.h>
#include <xen/list.h>
#include <xen/serial.h>
#include <xen/softirq.h>

int pdb_trace = 1;                                 /* debugging the debugger */

#define DEBUG_EXCEPTION     0x01
#define BREAKPT_EXCEPTION   0x03
#define PDB_LIVE_EXCEPTION  0x58
#define KEYPRESS_EXCEPTION  0x88

static const char hexchars[] = "0123456789abcdef";

#define PDB_BUFMAX 1024
static char pdb_in_buffer[PDB_BUFMAX];
static char pdb_out_buffer[PDB_BUFMAX];
static int  pdb_in_buffer_ptr;
static unsigned char  pdb_in_checksum;
static unsigned char  pdb_xmit_checksum;

void pdb_put_packet (unsigned char *buffer, int ack);

pdb_context_t pdb_ctx;
int pdb_continue_thread = 0;
int pdb_general_thread = 0;


enum pdb_bwc_page_action
{
  PDB_BWC_PAGE_ACCESS_SET,
  PDB_BWC_PAGE_ACCESS_CLEAR,
  PDB_BWC_PAGE_WRITE_SET,
  PDB_BWC_PAGE_WRITE_CLEAR,
  PDB_BWC_PAGE_READ_SET,
  PDB_BWC_PAGE_READ_CLEAR,
};
static char *pdb_bwc_page_action_s[] =
  { "ac set", "ac clr", "wr set", "wr clr", "rd set", "rd cler" };
int pdb_bwc_page (int action, unsigned long addr, int length, 
		  pdb_context_p ctx, int offset, void *s);

enum pdb_visit_page_action
{
  PDB_VISIT_PAGE_XEN_READ,
  PDB_VISIT_PAGE_XEN_WRITE,
  PDB_VISIT_PAGE_DOMAIN_READ,
  PDB_VISIT_PAGE_DOMAIN_WRITE,
  PDB_VISIT_PAGE_PROCESS_READ,
  PDB_VISIT_PAGE_PROCESS_WRITE,
};
static char *pdb_visit_page_action_s[] =
  { "xen rd", "xen wr", "dom rd", "dom wr", "proc rd", "proc wr" };

int pdb_visit_page (int action, unsigned long addr, int length,
                    pdb_context_p ctx, int offset, void *s);

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

unsigned char pdb_x86_bkpt = 0xcc;
unsigned int  pdb_x86_bkpt_length = 1;

/***********************************************************************/
/***********************************************************************/

static inline void pdb_put_char(unsigned char c)
{
    serial_putc(pdb_serhnd, c);
}

static inline unsigned char pdb_get_char(void)
{
    return serial_getc(pdb_serhnd);
}

/***********************************************************************/
/***********************************************************************/

/*
 * Prototype for function to process each page.  This function is called
 * once per page.
 *
 * action  : function specific
 * address : first byte of this page
 * length  : number of bytes to process on this page
 * offset  : number of bytes processed so far. can be used as
 *           an index into data.
 * data    : function specific.
 */

typedef int (pdb_invoke_ftype) (int action, unsigned long address, int length, 
				pdb_context_p ctx, int offset, void *data);

typedef struct pdb_invoke_args
{
  pdb_context_p context;
  unsigned long address;
  int length;
  int action;
  void *data;
} pdb_invoke_args_t, * pdb_invoke_args_p;


/*
 * call a particular function once per page given an address & length
 */

int
pdb_invoke(pdb_invoke_ftype *function, pdb_invoke_args_p args)
{
  int remaining;
  int bytes = 0;
  int length = args->length;
  unsigned long address = args->address;

  while ((remaining = (address + length - 1) - (address | (PAGE_SIZE - 1))) > 0)
  {
    bytes += (function)(args->action, address, length - remaining,
			args->context, address - args->address, args->data);
    length = remaining;
    address = (address | (PAGE_SIZE - 1)) + 1;
  }
  bytes += (function)(args->action, address, length,
                      args->context, address - args->address, args->data);
  return bytes;
}


/***********************************************************************/
/***********************************************************************/

/* BWC List Support: breakpoints, watchpoints, and catchpoints */

char *pdb_bwcpoint_type_s[] =                      /* enum pdb_bwcpoint_type */
  { "BP_SOFTWARE", "BP_HARDWARE", "WP_WRITE", "WP_READ", "WP_ACCESS" };

int pdb_set_watchpoint (pdb_bwcpoint_p bwc); 
int pdb_clear_watchpoint (pdb_bwcpoint_p bwc);

struct list_head pdb_bwc_list = LIST_HEAD_INIT(pdb_bwc_list);

void
pdb_bwc_list_add (pdb_bwcpoint_p bwc)
{
  list_add_tail(&bwc->list, &pdb_bwc_list);
}

void
pdb_bwc_list_remove (pdb_bwcpoint_p bwc)
{
  list_del(&bwc->list);
}

pdb_bwcpoint_p
pdb_bwc_list_search (unsigned long address, int length, pdb_context_p ctx)
{
  struct list_head *ptr;

  list_for_each (ptr, &pdb_bwc_list)
  {
    pdb_bwcpoint_p bwc = list_entry(ptr, pdb_bwcpoint_t, list);

    if (bwc->address == address &&
        bwc->length  == length)
    {
      return bwc;
    }
  }
  return (pdb_bwcpoint_p) 0;
}

pdb_bwcpoint_p
pdb_bwcpoint_search (unsigned long cr3, unsigned long address)
{
  pdb_context_t ctx;

  ctx.ptbr = cr3;
  return pdb_bwc_list_search (address, pdb_x86_bkpt_length, &ctx);
}

void
pdb_bwc_print (pdb_bwcpoint_p bwc)
{
    printk ("address: 0x%08lx, length: 0x%02x, type: 0x%x %s", 
	    bwc->address, bwc->length,
	    bwc->type, pdb_bwcpoint_type_s[bwc->type]);
}

void
pdb_bwc_print_list ()
{
  struct list_head *ptr;
  int counter = 0;

  list_for_each (ptr, &pdb_bwc_list)
  {
    pdb_bwcpoint_p bwc = list_entry(ptr, pdb_bwcpoint_t, list);
    printk ("  [%02d]  ", counter);   pdb_bwc_print(bwc);   printk ("\n");
    counter++;
  }
}

/***********************************************************************/
/***********************************************************************/

void
pdb_process_query (char *ptr)
{
    if (strcmp(ptr, "C") == 0)
    {
        /* empty string */
    }
    else if (strcmp(ptr, "fThreadInfo") == 0)
    {
        int buf_idx = 0;

	pdb_out_buffer[buf_idx++] = 'l';
	pdb_out_buffer[buf_idx++] = 0;
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
pdb_process_z (int onoff, char *ptr)
{
    int type = *(ptr++) - '0';
    int length;
    unsigned long addr;
    char *error = "E01";                                     /* syntax error */

    /* try to read ',addr,length' */
    if (   *(ptr++) == ','
	&& hexToInt(&ptr, (int *)&addr)
	&& *(ptr++) == ','
	&& hexToInt(&ptr, &length))
    {
	error = "OK";

	switch (type)
	{
	case PDB_BP_SOFTWARE:
	case PDB_BP_HARDWARE:
	{
	    if (onoff == 1)
	    {
	        pdb_bwcpoint_p bwc = (pdb_bwcpoint_p) xmalloc(sizeof(pdb_bwcpoint_t));

		bwc->address = addr;
		bwc->length = pdb_x86_bkpt_length;
		bwc->type = PDB_BP_SOFTWARE;
		bwc->user_type = type;
		memcpy (&bwc->context, &pdb_ctx, sizeof(pdb_context_t));

		if (length != pdb_x86_bkpt_length)
		{
		    printk("pdb warning: x86 bkpt length should be 1\n");
		}

		pdb_set_breakpoint (bwc);
	    }
	    else
	    {
	        pdb_clear_breakpoint (addr, pdb_x86_bkpt_length, &pdb_ctx);
	        pdb_bwcpoint_p bwc = pdb_bwc_list_search (addr, 1, &pdb_ctx);

		if (bwc == 0)
		{
		    error = "E03";                   /* breakpoint not found */
		    break;
		}

		pdb_write_memory (addr, 1, &bwc->original, &pdb_ctx);

		pdb_bwc_list_remove (bwc);
	    }
	    break;
	}
	case PDB_WP_WRITE:
	case PDB_WP_READ:
	case PDB_WP_ACCESS:
	{
	    if (onoff == 1)
	    {
	        pdb_bwcpoint_p bwc = (pdb_bwcpoint_p) xmalloc(sizeof(pdb_bwcpoint_t));

		bwc->address = addr;
		bwc->length = length;
		bwc->type = type;
		bwc->user_type = type;
		memcpy (&bwc->context, &pdb_ctx, sizeof(pdb_context_t));

		pdb_set_watchpoint (bwc);

		pdb_bwc_list_add (bwc);
	    }
	    else
	    {
	        pdb_bwcpoint_p bwc = pdb_bwc_list_search (addr, 1, &pdb_ctx);

		if (bwc == 0)
		{
		    error = "E03";                   /* watchpoint not found */
		    break;
		}

		pdb_clear_watchpoint (bwc);

		pdb_bwc_list_remove (bwc);
	    }
	    break;
	}
	default:
	{
	    printk ("pdb error: unknown Z command [%c]\n", type);
	    error = "E02";                                   /* syntax error */
	    break;
	}
	}
    }

    if (error)                               /* return value, including okay */
    {
	strcpy (pdb_out_buffer, error);
    }
}

void
pdb_process_pdb (char *ptr)
{
    unsigned long arg1, arg2;
    char *error = "E01";                                     /* syntax error */
    char command = *(ptr++);

    switch (command)
    {
    case 'c':                                             /* set pdb context */
    case 'C':
    {
        /* try to read two hex arguments ':arg1,arg2 */
        if (   *(ptr++) == ':'
	    && hexToInt(&ptr, (int *)&arg1)
	    && *(ptr++) == ','
	    && hexToInt(&ptr, (int *)&arg2))
	{
	    printk ("pdb: set context: domain:0x%lx process:0x%lx\n", 
		    arg1, arg2);
	    error = "OK";
	}

        pdb_ctx.domain  = arg1;
	pdb_ctx.process = arg2;
	pdb_ctx.valid   = 1;
	break;
    }
    case 't':                                          /* enable pdb tracing */
    case 'T':
    {
        /* read the trace level */
        if (   *(ptr++) == ':'
	    && hexToInt(&ptr, (int *)&pdb_trace))
	{
	    printk ("pdb: set trace level: 0x%x\n", pdb_trace);
	    error = "OK";
	}
	break;
    }
    case 'd':
    case 'D':                                              /* dump pdb state */
    {
        printk ("----------\n");
        printk ("pdb trace : %2d 0x%02x\n", pdb_trace, pdb_trace);
        printk ("pdb ctx domain  : %4d 0x%04x\n",
		pdb_ctx.domain, pdb_ctx.domain);
        printk ("        process : %4d 0x%04x\n",
		pdb_ctx.process, pdb_ctx.process);
        printk ("        sys call: %4d 0x%04x\n",
		pdb_ctx.system_call, pdb_ctx.system_call);
        printk ("bwc list:\n");
	pdb_bwc_print_list ();
        printk ("----------\n");
	error = "OK";
	break;
    }
    default:
    {
        printk ("pdb error: unknown pdb dot command [%c]\n", command);
	error = "E02";                                       /* syntax error */
	break;
    }
    }

    if (error)                               /* return value, including okay */
    {
	strcpy (pdb_out_buffer, error);
    }
}

void
pdb_read_regs (char *buffer, struct pt_regs *regs)
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
    mem2hex ((char *)&regs->xcs, &buffer[idx], sizeof(regs->xcs));
    idx += sizeof(regs->xcs) * 2;
    mem2hex ((char *)&regs->xss, &buffer[idx], sizeof(regs->xss));
    idx += sizeof(regs->xss) * 2;
    mem2hex ((char *)&regs->xds, &buffer[idx], sizeof(regs->xds));
    idx += sizeof(regs->xds) * 2;
    mem2hex ((char *)&regs->xes, &buffer[idx], sizeof(regs->xes));
    idx += sizeof(regs->xes) * 2;
    mem2hex ((char *)&regs->xfs, &buffer[idx], sizeof(regs->xfs));
    idx += sizeof(regs->xfs) * 2;
    mem2hex ((char *)&regs->xgs, &buffer[idx], sizeof(regs->xgs));
}

/* at this point we allow any register to be changed, caveat emptor */
void
pdb_write_regs (struct pt_regs *regs, char *buffer)
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
    hex2mem(buffer, (char *)&regs->xcs, sizeof(regs->xcs));
    buffer += sizeof(regs->xcs) * 2;
    hex2mem(buffer, (char *)&regs->xss, sizeof(regs->xss));
    buffer += sizeof(regs->xss) * 2;
    hex2mem(buffer, (char *)&regs->xds, sizeof(regs->xds));
    buffer += sizeof(regs->xds) * 2;
    hex2mem(buffer, (char *)&regs->xes, sizeof(regs->xes));
    buffer += sizeof(regs->xes) * 2;
    hex2mem(buffer, (char *)&regs->xfs, sizeof(regs->xfs));
    buffer += sizeof(regs->xfs) * 2;
    hex2mem(buffer, (char *)&regs->xgs, sizeof(regs->xgs));
}

int
pdb_process_command (char *ptr, struct pt_regs *regs, unsigned long cr3,
		     int sigval)
{
    int length;
    unsigned long addr;
    int ack = 1;                           /* wait for ack in pdb_put_packet */
    int go = 0;

    PDBTRC(1,printk("pdb: [%s]\n", ptr));

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
	PDBTRC(1,printk ("pdb change context (dom:%d, proc:%d) now 0x%lx\n",
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

	    /* this is always in a process context */
	    pdb_read_memory (pdb_system_call_eflags_addr, sizeof(eflags), 
			     (u_char *)&eflags, &pdb_ctx);
	    eflags |= X86_EFLAGS_TF;
	    pdb_write_memory (pdb_system_call_eflags_addr, sizeof(eflags), 
			      (u_char *)&eflags, &pdb_ctx);
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

	    /* this is always in a process context */
	    pdb_read_memory (pdb_system_call_eflags_addr, sizeof(eflags), 
			     (u_char *)&eflags, &pdb_ctx);
	    eflags &= ~X86_EFLAGS_TF;
	    pdb_write_memory (pdb_system_call_eflags_addr, sizeof(eflags), 
			      (u_char *)&eflags, &pdb_ctx);
	}

        regs->eflags &= ~X86_EFLAGS_TF;
        return 1;                         /* jump out before replying to gdb */
        /* not reached */
    }
    case 'd':
        break;
    case 'D':                                                      /* detach */
        go = 1;
        break;
    case 'g':                       /* return the value of the CPU registers */
    {
        pdb_read_regs (pdb_out_buffer, regs);
        break;
    }
    case 'G':              /* set the value of the CPU registers - return OK */
    {
        pdb_write_regs (regs, ptr);
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

		    pdb_page_fault_possible = 2;
		    pdb_page_fault = 0;

	    {
	        u_char *buffer = (u_char *) xmalloc (length);
		if (!buffer)
		{
		    printk ("pdb error: xmalloc failure\n");
		    break;
		}
		pdb_read_memory (addr, length, buffer, &pdb_ctx);
		mem2hex (buffer, pdb_out_buffer, length); 
		xfree(buffer);
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
        if (   hexToInt (&ptr, (int *)&addr)
	    && *(ptr++) == ','
            && hexToInt (&ptr, &length)
	    && *(ptr++) == ':')
	{
	    pdb_page_fault_possible = 3;
	    pdb_page_fault = 0;

	    {
	        u_char *buffer = (u_char *) xmalloc (length);
		if (!buffer)
		{
		    printk ("pdb error: xmalloc failure\n");
		    break;
		}
	        hex2mem (ptr, buffer, length);
		pdb_write_memory (addr, length, buffer, &pdb_ctx);
		xfree(buffer);
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
        }
        break;
    }
    case 'Z':                                                         /* set */
    {
        pdb_process_z (1, ptr);
	break;
    }
    case 'z':                                                       /* clear */
    {
        pdb_process_z (0, ptr);
	break;
    }
    case '.':                                     /* pdb specific extensions */
    {
        pdb_process_pdb (ptr);
	break;
    }
    default:
    {
        PDBTRC(1,printk ("pdb warning: ignoring unknown command.\n"));
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

int pdb_serial_input(u_char c, struct pt_regs *regs)
{
    int out = 1;
    int loop, count;
    unsigned long cr3;

    __asm__ __volatile__ ("movl %%cr3,%0" : "=r" (cr3) : );

    switch (pdb_debug_state)
    {
    case 0:                         /* not currently processing debug string */
        if ( c == '$' )                                      /* start token */
	{
	    pdb_debug_state = 1;
	    pdb_in_buffer_ptr = 0;
	    pdb_in_checksum = 0;
	    pdb_xmit_checksum = 0;
	}
	else 
	{
	    out = 0;
	}
	break;
    case 1:                                                       /* saw '$' */
        if ( c == '#' )                                    /* checksum token */
	{
	    pdb_debug_state = 2;
	    pdb_in_buffer[pdb_in_buffer_ptr] = 0;
	}
	else
	{
	    pdb_in_checksum += c;
	    pdb_in_buffer[pdb_in_buffer_ptr++] = c;
	}
	break;
    case 2:                                            /* 1st checksum digit */
        pdb_xmit_checksum = hex(c) << 4;
	pdb_debug_state = 3;
	break;
    case 3:                                            /* 2nd checksum digit */
        pdb_xmit_checksum += hex(c);
	if (pdb_in_checksum != pdb_xmit_checksum) 
	{
	    pdb_put_char('-');                           /* checksum failure */
	    printk ("pdb error: checksum failure [%s.%02x.%02x]\n",
		    pdb_in_buffer, pdb_in_checksum, pdb_xmit_checksum);
	}
	else 
	{
	    pdb_put_char('+');                              /* checksum okay */
	    if ( pdb_in_buffer_ptr > 1 && pdb_in_buffer[2] == ':' ) 
	    {
	        pdb_put_char(pdb_in_buffer[0]);
		pdb_put_char(pdb_in_buffer[1]);
		/* remove sequence chars from buffer */
		count = strlen(pdb_in_buffer);
		for (loop = 3; loop < count; loop++)
		    pdb_in_buffer[loop - 3] = pdb_in_buffer[loop];
	    }

	    pdb_process_command (pdb_in_buffer, regs, cr3,
				 PDB_LIVE_EXCEPTION);
	}
	pdb_debug_state = 0;
	break;
    }

    return out;
}

/***********************************************************************/
/***********************************************************************/

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
        ch = *mem;
	mem ++;
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
        *mem = ch;
	mem++;
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

/* READ / WRITE MEMORY */
int pdb_change_page (u_char *buffer, int length,
		     unsigned long cr3, unsigned long addr, int rw);
int pdb_visit_memory (unsigned long addr, int length, unsigned char *data,
		      pdb_context_p ctx, pdb_generic_action action);

int 
pdb_read_memory (unsigned long addr, int length, unsigned char *data,
		 pdb_context_p ctx)
{
    return pdb_visit_memory (addr, length, data, ctx, __PDB_GET);
}

int
pdb_write_memory (unsigned long addr, int length, unsigned char *data,
		  pdb_context_p ctx)
{
    return pdb_visit_memory (addr, length, data, ctx, __PDB_SET);
}

/*
 * either read or write a block of memory 
 */

int
pdb_visit_memory (unsigned long addr, int length, unsigned char *data,
		  pdb_context_p ctx, pdb_generic_action action)
{
    int return_value;
    pdb_invoke_args_t args;

    pdb_page_fault_possible = 4;
    pdb_page_fault = 0;

    args.context = ctx;
    args.address = addr;
    args.length = length;
    args.data = data;

    if (addr >= PAGE_OFFSET)                                          /* Xen */
    {
        args.action = (action == __PDB_GET) ? PDB_VISIT_PAGE_XEN_READ
                                            : PDB_VISIT_PAGE_XEN_WRITE;
    }
    else if (pdb_ctx.process != -1)                               /* Process */
    {
        args.action = (action == __PDB_GET) ? PDB_VISIT_PAGE_PROCESS_READ
                                            : PDB_VISIT_PAGE_PROCESS_WRITE;
    }
    else                                                           /* Domain */
    {
        args.action = (action == __PDB_GET) ? PDB_VISIT_PAGE_DOMAIN_READ
                                            : PDB_VISIT_PAGE_DOMAIN_WRITE;
    }

    return_value = pdb_invoke (pdb_visit_page, &args);

    pdb_page_fault_possible = 0;
    if (pdb_page_fault || return_value < 0)
    {
        strcpy (pdb_out_buffer, "E03");
    }
  
    return return_value;
}

/*
 * either read or write a single page
 */

int 
pdb_visit_page (int action, unsigned long addr, int length, 
		pdb_context_p ctx, int offset, void *data)
{
  int rval;
  
  PDBTRC(2,printk ("visit: %s [0x%08lx:%x] 0x%x (0x%p)\n",
		   pdb_visit_page_action_s[action], 
		   addr, length, offset, data));

  switch (action)
  {
  case PDB_VISIT_PAGE_XEN_READ :
  {
      memcpy ((void *) data, (void *) addr, length);
      rval = length;;
      break;
  }
  case PDB_VISIT_PAGE_XEN_WRITE :
  {
      memcpy ((void *) addr, (void *) data, length);
      rval = length;
      break;
  }
  case PDB_VISIT_PAGE_DOMAIN_READ :
  case PDB_VISIT_PAGE_DOMAIN_WRITE :
  {
      rval = pdb_change_page (data, length, ctx->ptbr, addr,
               (action == PDB_VISIT_PAGE_DOMAIN_READ) ? __PDB_GET : __PDB_SET);
      break;
  }
  case PDB_VISIT_PAGE_PROCESS_READ :
  case PDB_VISIT_PAGE_PROCESS_WRITE :
  {
      u_char pdb_linux_visit_page(int pid, unsigned long cr3, unsigned long addr, int length, unsigned char *buffer, int action);

      rval = pdb_linux_visit_page (ctx->process, ctx->ptbr, addr, length, data,
              (action == PDB_VISIT_PAGE_PROCESS_READ) ? __PDB_GET : __PDB_SET);
      break;
  }
  default :
  {
      printk ("pdb error: unknown visit page action [%d]\n", action);
      break;
  }
  }

  return 1;
}

/**************************************/
/**************************************/

int
pdb_read_page(u_char *buffer, int length,
		unsigned long cr3, unsigned long addr)
{
    return pdb_change_page(buffer, length, cr3, addr, __PDB_GET);
}

int
pdb_write_page(u_char *buffer, int length,
	       unsigned long cr3, unsigned long addr)
{
    return pdb_change_page(buffer, length, cr3, addr, __PDB_SET);
}

/*
 * Change memory in one page of an address space.
 * Read or write "length" bytes at "address" into/from "buffer"
 * from the virtual address space referenced by "cr3".
 * Return the number of bytes read, 0 if there was a problem.
 */

int
pdb_change_page(u_char *buffer, int length,
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
	if (pdb_page_fault_possible)
	{
	    pdb_page_fault = 1;
	    PDBTRC2(1,printk("pdb: expected L2 error %d (0x%lx)\n", 
			     pdb_page_fault_possible, addr));
	}
	else
	{
	    struct domain *p = find_domain_by_id(0);
	    printk ("pdb error: cr3: 0x%lx    dom0cr3:  0x%lx\n",  cr3,
		    p->mm.shadow_mode ? pagetable_val(p->mm.shadow_table)
		    : pagetable_val(p->mm.pagetable));
	    put_domain(p);
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
		PDBTRC(1,printk ("pdb: L1 error (0x%lx)\n", addr));
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
    case __PDB_GET:                                                  /* read */
    {
        memcpy (buffer, page, length);
	bytes = length;

	break;
    }
    case __PDB_SET:                                                 /* write */
    {
        memcpy (page, buffer, length);
	bytes = length;
	break;
    }
    default:                                                      /* unknown */
    {
        printk ("pdb error: unknown RW flag: %d\n", rw);
	return 0;
    }
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
/***********************************************************************/

/* BREAKPOINTS */

int
pdb_set_breakpoint (pdb_bwcpoint_p bwc)
{
    pdb_read_memory (bwc->address, 1, &bwc->original, &bwc->context);
    pdb_write_memory (bwc->address, 1, &pdb_x86_bkpt, &bwc->context);

    pdb_bwc_list_add (bwc);

    return 0;
}

int
pdb_clear_breakpoint (unsigned long address, int length, pdb_context_p ctx)
{
    int error = 0;
    pdb_bwcpoint_p bwc = pdb_bwc_list_search (address, 1, &pdb_ctx);

    if (bwc == 0)
    {
      error = 3;                                     /* breakpoint not found */
    }

    pdb_write_memory (address, 1, &bwc->original, &pdb_ctx);
    
    pdb_bwc_list_remove (bwc);

    return error;
}

/***********************************************************************/
/***********************************************************************/

/* WATCHPOINTS */

int pdb_process_watchpoint (pdb_bwcpoint_p bwc, pdb_generic_action action);

int
pdb_set_watchpoint (pdb_bwcpoint_p bwc)
{
    return pdb_process_watchpoint (bwc, __PDB_SET);
}

int
pdb_clear_watchpoint (pdb_bwcpoint_p bwc)
{
    return pdb_process_watchpoint (bwc, __PDB_CLEAR);
}

/* set or clear watchpoint */
int
pdb_process_watchpoint (pdb_bwcpoint_p bwc, pdb_generic_action action)
{
    int return_value;
    pdb_invoke_args_t args;

    args.context = &bwc->context;
    args.address = bwc->address;
    args.length = bwc->length;
    args.data = bwc;
    switch (bwc->type)
    {
    case PDB_WP_WRITE :
    {
        args.action = (action == __PDB_SET) ? PDB_BWC_PAGE_WRITE_SET 
                                            : PDB_BWC_PAGE_WRITE_CLEAR;
	break;       
    }
    case PDB_WP_READ :
    {
        args.action = (action == __PDB_SET) ? PDB_BWC_PAGE_READ_SET 
                                            : PDB_BWC_PAGE_READ_CLEAR;
	break;       
    }
    case PDB_WP_ACCESS :
    {
        args.action = (action == __PDB_SET) ? PDB_BWC_PAGE_ACCESS_SET 
                                            : PDB_BWC_PAGE_ACCESS_CLEAR;
	break;       
    }
    default :
    {
        printk ("pdb error: incorrect watchpoint type [%d][%s]",
		bwc->type, pdb_bwcpoint_type_s[bwc->type]);
        break;
    }
    }

    return_value = pdb_invoke (pdb_bwc_page, &args);

    if (return_value < 0)
    {
         strcpy (pdb_out_buffer, "E03");
    }

    return return_value;
}

/*
 * set or clear watchpoint for a single page 
 */

int 
pdb_bwc_page (int action, unsigned long addr, int length, 
	      pdb_context_p ctx, int offset, void *data)
{
    int rval = 0;

    printk ("bwc: %s [0x%08lx:%x] 0x%x (0x%p)\n",
	    pdb_bwc_page_action_s[action], addr, length, offset, data);

    switch (action)
    {
    case PDB_BWC_PAGE_ACCESS_SET :
    case PDB_BWC_PAGE_ACCESS_CLEAR : 
    case PDB_BWC_PAGE_WRITE_SET :
    case PDB_BWC_PAGE_WRITE_CLEAR :
    case PDB_BWC_PAGE_READ_SET :
    case PDB_BWC_PAGE_READ_CLEAR :
    {
        printk ("fill in the blank [%s:%d]\n", __FILE__, __LINE__);
        break;
    }
    default :
    {
        printk ("pdb error: unknown bwc page action [%d]\n", action);
	break;
    }
    }

    return rval;
}

/***********************************************************************/
/***********************************************************************/

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

	while (count < PDB_BUFMAX)
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

#ifdef GDB_50_SUPPORT
		if (buffer[2] == ':')
		  { printk ("pdb: obsolete gdb packet (sequence ID)\n"); }
#endif
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
			 struct pt_regs *xen_regs)
{
    int signal = 0;
    struct pdb_bwcpoint* bkpt;
    int watchdog_save;
    unsigned long cr3;

    __asm__ __volatile__ ("movl %%cr3,%0" : "=r" (cr3) : );

PDBTRC(4,printk("pdb handle exception\n"));
PDBTRC(4,printk("    cr3: 0x%lx\n", cr3));
PDBTRC(4,printk("    eip: 0x%lx\n", xen_regs->eip));
PDBTRC(4,printk("    except vector: 0x%x\n", exceptionVector));
PDBTRC(4,printk("    xcs: 0x%x\n", xen_regs->xcs));
PDBTRC(4,printk("    sys call next addr: 0x%lx\n", pdb_system_call_next_addr));
PDBTRC(4,printk("    stepping: 0x%x\n", pdb_stepping));
PDBTRC(4,printk("    system_call: 0x%x\n", pdb_system_call));

    /* If the exception is an int3 from user space then pdb is only
       interested if it re-wrote an instruction set the breakpoint.
       This occurs when leaving a system call from a domain.
    */
    bkpt = pdb_bwcpoint_search(cr3, xen_regs->eip - 1);
    if ( bkpt == NULL &&
         exceptionVector == 3 &&
	 (xen_regs->xcs & 3) == 3 && 
	 xen_regs->eip != pdb_system_call_next_addr + 1)
    {
        PDBTRC(1,printk("pdb: user bkpt (0x%x) at 0x%x:0x%lx:0x%lx 0x%lx\n", 
			exceptionVector, xen_regs->xcs & 3, cr3, 
			xen_regs->eip, pdb_system_call_next_addr));
	return 1;
    }

    /*
     * If PDB didn't set the breakpoint, is not single stepping, 
     * is not entering a system call in a domain,
     * the user didn't press the magic debug key, 
     * then we don't handle the exception.
     */
    if ( (bkpt == NULL) &&
         !pdb_stepping && 
	 !pdb_system_call &&
	 xen_regs->eip != pdb_system_call_next_addr + 1 &&
	 (exceptionVector != KEYPRESS_EXCEPTION) &&
	 xen_regs->eip < 0xc0000000)  /* Linux-specific for now! */
    {
        PDBTRC(1,printk("pdb: user bkpt (0x%x) at 0x%lx:0x%lx\n", 
		     exceptionVector, cr3, xen_regs->eip));
	return 1;
    }

    printk("pdb_handle_exception [0x%x][0x%lx:0x%lx]\n",
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

    /* returning to user space after a system call */
    if ( xen_regs->eip == pdb_system_call_next_addr + 1)
    {
	 printk("BUG ******** \n");
         printk("BUG return to user space bug\n");
	 printk("BUG ******** \n");

        /*
	 * BUG: remember to delete the breakpoint!!!
	 *       
	 */

        /* this is always in a process context */
        pdb_write_memory (pdb_system_call_next_addr,
			  sizeof(pdb_system_call_leave_instr),
			  &pdb_system_call_leave_instr, &pdb_ctx);
 
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


    if ( exceptionVector == BREAKPT_EXCEPTION && bkpt != NULL)
    {
        /* Executed Int3: replace breakpoint byte with real program byte. */
        xen_regs->eip--;
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

void __pdb_key_pressed(void)
{
    struct pt_regs *regs = (struct pt_regs *)get_execution_context();
    pdb_handle_exception(KEYPRESS_EXCEPTION, regs);
}

void pdb_key_pressed(u_char key, void *dev_id, struct pt_regs *regs) 
{
    raise_softirq(DEBUGGER_SOFTIRQ);
}

void initialize_pdb()
{
    extern char opt_pdb[];

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

    open_softirq(DEBUGGER_SOFTIRQ, __pdb_key_pressed);
    add_key_handler('D', pdb_key_pressed, "enter pervasive debugger");

    pdb_initialized = 1;
}

/***********************************************************************/
/***********************************************************************/

