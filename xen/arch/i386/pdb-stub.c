#include <xeno/lib.h>
#include <xeno/sched.h>
#include <asm-i386/ptrace.h>
#include <xeno/keyhandler.h> 
#include <asm/pdb.h>
#include <xeno/list.h>

#define BUFMAX 400

#define PDB_DOMAIN_OFFSET 2              /* all domains are positive numbers */

static const char hexchars[]="0123456789abcdef";

static int remote_debug;

int pdb_foobar = 0x123456;                                        /* testing */
char *pdb_foobaz = "cambridge";                                   /* testing */

#define PDB_BUFMAX 1024
static char pdb_in_buffer[PDB_BUFMAX];
static char pdb_out_buffer[PDB_BUFMAX];
static char pdb_buffer[PDB_BUFMAX];
static int  pdb_in_buffer_ptr;
static unsigned char  pdb_in_checksum;
static unsigned char  pdb_xmit_checksum;

static int pdb_ctrl_thread = -1;
static int pdb_info_thread = -1;
static int pdb_stepping = 0;

void pdb_put_packet (unsigned char *buffer, int ack);
void pdb_put_char (u_char c);
u_char pdb_get_char ();

static volatile int mem_err = 0;
void set_mem_err (void)                                   /* NOT USED YET... */
{
    mem_err = 1;
}

/* These are separate functions so that they are so short and sweet
   that the compiler won't save any registers (if there is a fault
   to mem_fault, they won't get restored, so there better not be any
   saved).  */
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
        struct task_struct *p = &idle0_task;
        u_long flags;
	int count = 0, buf_idx = 0;

        read_lock_irqsave (&tasklist_lock, flags);

	pdb_out_buffer[buf_idx++] = 'm';
        while ( (p = p->next_task) != &idle0_task )
	{
	    domid_t domain = p->domain + PDB_DOMAIN_OFFSET;

	    if (count > 0)
	        pdb_out_buffer[buf_idx++] = ',';
	    /*
              if (domain < 0)
              {   pdb_out_buffer[buf_idx++] = '-'; domain = domain * -1; }
	    */
	    if (domain > 15)
	    {
	        pdb_out_buffer[buf_idx++] = hexchars[domain >> 4];
	    }
	    pdb_out_buffer[buf_idx++] = hexchars[domain % 16];
	    count++;
	}
	pdb_out_buffer[buf_idx++] = 'l';
	pdb_out_buffer[buf_idx++] = 0;

        read_unlock_irqrestore(&tasklist_lock, flags);
    }
    else if (strcmp(ptr, "sThreadInfo") == 0)
    {
    }
    else if (strncmp(ptr, "ThreadExtraInfo,", 16) == 0)
    {
        int thread = 0;
	char *message = "whatever!";

	ptr += 16;
        if (hexToInt (&ptr, &thread))
	{
            mem2hex ((char *)message, pdb_out_buffer, strlen(message) + 1);
	}
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
        printk("pdb_process_query: unknown query [%s]\n", ptr);
    }
}

int
pdb_process_command (char *ptr, struct pt_regs *regs)
{
    int sigval = 10;
    int length;
    unsigned long addr;
    int ack = 1;                           /* wait for ack in pdb_put_packet */
    int go = 0;

    DPRINTK("pdb: [%s]\n", ptr);

    pdb_out_buffer[0] = 0;

    switch (*ptr++)
    {
    case '?':
        pdb_out_buffer[0] = 'S';
        pdb_out_buffer[1] = hexchars[sigval >> 4];
        pdb_out_buffer[2] = hexchars[sigval % 16];
        pdb_out_buffer[3] = 0;
        break;
    case 'S':                                        /* step with signal */
    case 's':                                                    /* step */
        regs->eflags |= 0x100;
        pdb_stepping = 1;
        return 1;                                        
        /* not reached */
    case 'C':                                    /* continue with signal */
    case 'c':                                                /* continue */
        regs->eflags &= ~0x100;
        /* jump out before replying to gdb */
        return 1;
        /* not reached */
    case 'd':
        remote_debug = !(remote_debug);               /* toggle debug flag */
        break;
    case 'D':                                                  /* detach */
        return go;
        /* not reached */
    case 'g':                   /* return the value of the CPU registers */
    {
        int idx = 0;
        mem2hex ((char *)&regs->eax, &pdb_out_buffer[idx], sizeof(regs->eax));
        idx += sizeof(regs->eax) * 2;
        mem2hex ((char *)&regs->ecx, &pdb_out_buffer[idx], sizeof(regs->ecx));
        idx += sizeof(regs->ecx) * 2;
        mem2hex ((char *)&regs->edx, &pdb_out_buffer[idx], sizeof(regs->edx));
        idx += sizeof(regs->edx) * 2;
        mem2hex ((char *)&regs->ebx, &pdb_out_buffer[idx], sizeof(regs->ebx));
        idx += sizeof(regs->ebx) * 2;
        mem2hex ((char *)&regs->esp, &pdb_out_buffer[idx], sizeof(regs->esp));
        idx += sizeof(regs->esp) * 2;
        mem2hex ((char *)&regs->ebp, &pdb_out_buffer[idx], sizeof(regs->ebp));
        idx += sizeof(regs->ebp) * 2;
        mem2hex ((char *)&regs->esi, &pdb_out_buffer[idx], sizeof(regs->esi));
        idx += sizeof(regs->esi) * 2;
        mem2hex ((char *)&regs->edi, &pdb_out_buffer[idx], sizeof(regs->edi));
        idx += sizeof(regs->edi) * 2;
        mem2hex ((char *)&regs->eip, &pdb_out_buffer[idx], sizeof(regs->eip));
        idx += sizeof(regs->eip) * 2;
        mem2hex ((char *)&regs->eflags, &pdb_out_buffer[idx], sizeof(regs->eflags));
        idx += sizeof(regs->eflags) * 2;
        mem2hex ((char *)&regs->xcs, &pdb_out_buffer[idx], sizeof(regs->xcs));
        idx += sizeof(regs->xcs) * 2;
        mem2hex ((char *)&regs->xss, &pdb_out_buffer[idx], sizeof(regs->xss));
        idx += sizeof(regs->xss) * 2;
        mem2hex ((char *)&regs->xds, &pdb_out_buffer[idx], sizeof(regs->xds));
        idx += sizeof(regs->xds) * 2;
        mem2hex ((char *)&regs->xes, &pdb_out_buffer[idx], sizeof(regs->xes));
        idx += sizeof(regs->xes) * 2;
        mem2hex ((char *)&regs->xfs, &pdb_out_buffer[idx], sizeof(regs->xfs));
        idx += sizeof(regs->xfs) * 2;
        mem2hex ((char *)&regs->xgs, &pdb_out_buffer[idx], sizeof(regs->xgs));

        /*
          TRC(printk ("  reg: %s \n", pdb_out_buffer));
          TRC(printk ("  ebx: 0x%08lx\n", regs->ebx));
          TRC(printk ("  ecx: 0x%08lx\n", regs->ecx));
          TRC(printk ("  edx: 0x%08lx\n", regs->edx));
          TRC(printk ("  esi: 0x%08lx\n", regs->esi));
          TRC(printk ("  edi: 0x%08lx\n", regs->edi));
          TRC(printk ("  ebp: 0x%08lx\n", regs->ebp));
          TRC(printk ("  eax: 0x%08lx\n", regs->eax));
          TRC(printk ("  xds: 0x%08x\n", regs->xds));
          TRC(printk ("  xes: 0x%08x\n", regs->xes));
          TRC(printk ("  xfs: 0x%08x\n", regs->xfs));
          TRC(printk ("  xgs: 0x%08x\n", regs->xgs));
          TRC(printk ("  eip: 0x%08lx\n", regs->eip));
          TRC(printk ("  xcs: 0x%08x\n", regs->xcs));
          TRC(printk ("  efl: 0x%08lx\n", regs->eflags));
          TRC(printk ("  esp: 0x%08lx\n", regs->esp));
          TRC(printk ("  xss: 0x%08x\n", regs->xss));
        */

        break;
    }
    case 'G':          /* set the value of the CPU registers - return OK */
        break;

    case 'H':
    {
        int thread;
        char *next = &ptr[1];
        if (hexToInt (&next, &thread))
        {
            if (thread > 0)
            {
                thread = thread - PDB_DOMAIN_OFFSET;
            }
            if (*ptr == 'c')
            {
                pdb_ctrl_thread = thread;
            }
            else if (*ptr == 'g')
            {
                pdb_info_thread = thread;
            }
            else
            {
                printk ("ack, unknown command %c (thread: %d)\n", 
                        *ptr, thread);
            }
        }
        strcpy (pdb_out_buffer, "OK");
        break;
    }
    case 'k':                                            /* kill request */
    {
        strcpy (pdb_out_buffer, "OK");                    /* ack for fun */
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
                    mem_err = 0;

                    if (pdb_info_thread >= 0)
                    {
                        pdb_get_values(pdb_info_thread, pdb_buffer, addr, length);
                        mem2hex (pdb_buffer, pdb_out_buffer, length);
                    }
                    else
                        mem2hex ((char *) addr, pdb_out_buffer, length); 
                    if (mem_err)
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
                        mem_err = 0;

                        pdb_set_values(pdb_info_thread, 
                                       ptr, addr, length);

                        if (mem_err)
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
        int thread;
        if (hexToInt (&ptr, &thread))
        {
            thread -= PDB_DOMAIN_OFFSET;
            struct task_struct *p = find_domain_by_id(thread);
            if (p == NULL)
            {
                strcpy (pdb_out_buffer, "E00");
            }
            else
            {
                strcpy (pdb_out_buffer, "OK");
            }
            put_task_struct(p);
        }
        break;
    }
    }                                                          /* switch */

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
	    printk ("checksum failure [%s.%02x.%02x]\n", pdb_in_buffer,
		    pdb_in_checksum, pdb_xmit_checksum);
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

	    pdb_process_command (pdb_in_buffer, regs);
	}
	pdb_debug_state = 0;
	break;
    }

    return out;
}

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

void pdb_bkpt_add (unsigned long address)
{
    struct pdb_breakpoint *bkpt = kmalloc(sizeof(*bkpt), GFP_KERNEL);
    bkpt->address = address;
    list_add(&bkpt->list, &breakpoints.list);
}

/*
 * Check to see of the breakpoint is in the list of known breakpoints 
 * Return 1 if it has been set, 0 otherwise.
 */
struct pdb_breakpoint* pdb_bkpt_search (unsigned long address)
{
    struct list_head *list_entry;
    struct pdb_breakpoint *bkpt;

    list_for_each(list_entry, &breakpoints.list)
    {
        bkpt = list_entry(list_entry, struct pdb_breakpoint, list);
	if ( bkpt->address == address )
            return bkpt;
    }

    return NULL;
}

/*
 * Remove a breakpoint to the list of known breakpoints.
 * Return 1 if the element was not found, otherwise 0.
 */
int pdb_bkpt_remove (unsigned long address)
{
    struct list_head *list_entry;
    struct pdb_breakpoint *bkpt;

    list_for_each(list_entry, &breakpoints.list)
    {
        bkpt = list_entry(list_entry, struct pdb_breakpoint, list);
	if ( bkpt->address == address )
	{
            list_del(&bkpt->list);
            kfree(bkpt);
            return 0;
	}
    }

    return 1;
}

/***********************************************************************/

void breakpoint(void);

int pdb_initialized = 0;
int pdb_high_bit = 1;

void pdb_put_char (u_char c)
{
    extern void   debug_putchar(u_char);
    u_char cc = pdb_high_bit ? c | 0x80 : c;
    debug_putchar(cc);
}

u_char pdb_get_char ()
{
    extern u_char debug_getchar();
    u_char cc = debug_getchar();
    return cc & 0x7f;
}

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
		    printk ("gdb packet found with sequence ID\n");
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
#define DEBUG_EXCEPTION      1
#define BREAKPT_EXCEPTION    3
#define KEYPRESS_EXCEPTION 136
int pdb_handle_exception(int exceptionVector,
			 struct pt_regs *xen_regs)
{
    int signal = 0;

    /*
     * If PDB didn't set the breakpoint, is not single stepping, and the user
     * didn't press the magic debug key, then we don't handle the exception.
     */
    if ( (pdb_bkpt_search(xen_regs->eip - 1) == NULL) &&
         !pdb_stepping && (exceptionVector != KEYPRESS_EXCEPTION) )
    {
        DPRINTK("pdb: external breakpoint at 0x%lx\n", xen_regs->eip);
	return 1;
    }

    printk("pdb_handle_exception [0x%x][0x%lx]\n",
           exceptionVector, xen_regs->eip);

    if ( pdb_stepping )
    {
        /* Stepped one instruction; now return to normal execution. */
        xen_regs->eflags &= ~0x100;
        pdb_stepping = 0;
    }

    if ( exceptionVector == BREAKPT_EXCEPTION )
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
        printk("can't generate signal for unknown exception vector %d\n",
               exceptionVector);
        break;
    }

    pdb_out_buffer[0] = 'S';
    pdb_out_buffer[1] = hexchars[signal >> 4];
    pdb_out_buffer[2] = hexchars[signal % 16];
    pdb_out_buffer[3] = 0;
    pdb_put_packet(pdb_out_buffer, 1);

    do {
        pdb_out_buffer[0] = 0;
	pdb_get_packet(pdb_in_buffer);
    }
    while ( pdb_process_command(pdb_in_buffer, xen_regs) == 0 );

    return 0;
}

void pdb_key_pressed(u_char key, void *dev_id, struct pt_regs *regs) 
{
    pdb_handle_exception(136, regs);
    return;
}

void initialize_pdb()
{
    extern char opt_pdb[];
    int pdb_com_port;

    /* Certain state must be initialised even when PDB will not be used. */
    breakpoints.address = 0;
    INIT_LIST_HEAD(&breakpoints.list);
    pdb_stepping = 0;

    if ( strncmp(opt_pdb, "com", 3) == 0 )
    {
        extern void debug_set_com_port(int port);

        pdb_com_port = opt_pdb[3] - '0';                 /* error checking ? */
	debug_set_com_port(pdb_com_port);
	pdb_high_bit = opt_pdb[4] == 'H' ? 1 : 0;
    }
    else
    {
        if ( strcmp(opt_pdb, "none") != 0 )
	    printk ("pdb: unknown option\n");
        return;
    }

    printk("Initializing pervasive debugger (PDB) [%s] port %d, high %d\n",
           opt_pdb, pdb_com_port, pdb_high_bit);

    /* ack any spurrious gdb packets */
    pdb_put_char ('+');

    /* serial console */
    add_key_handler('D', pdb_key_pressed, "enter pervasive debugger");

    pdb_initialized = 1;
}

void breakpoint(void)
{
    if ( pdb_initialized )
        asm("int $3");
}
