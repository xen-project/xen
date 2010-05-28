/* Low level interface to ptrace, for the remote server for GDB.
   Copyright 1995, 1996, 1998, 1999, 2000, 2001, 2002, 2003, 2004
   Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "server.h"
#include "linux-low.h"

#include <sys/wait.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/dir.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <xenctrl.h>

#define TRACE_ENTER /* printf("enter %s\n", __FUNCTION__) */

static xc_interface *xc_handle;

static inline int
curvcpuid()
{
  struct process_info *process;
  if (current_inferior == NULL)
      return 0;
  process = get_thread_process(current_inferior);
  return (process->thread_known ? process->tid : 0);

}

struct inferior_list all_processes;
static int current_domid;
static int expect_signal = 0;
static int signal_to_send = 0; 
static void linux_resume (struct thread_resume *resume_info);
static void linux_set_inferior (void);

int debug_threads;
int using_threads;
extern int isfile;

struct pending_signals
{
  int signal;
  struct pending_signals *prev;
};

#define PTRACE_ARG3_TYPE long
#define PTRACE_XFER_TYPE long

static int use_regsets_p = 1;


#define pid_of(proc) ((proc)->head.id)

/* FIXME: Delete eventually.  */
#define inferior_pid (pid_of (get_thread_process (current_inferior)))

/* This function should only be called if the process got a SIGTRAP.
   The SIGTRAP could mean several things.

   On i386, where decr_pc_after_break is non-zero:
   If we were single-stepping this process using PTRACE_SINGLESTEP,
   we will get only the one SIGTRAP (even if the instruction we
   stepped over was a breakpoint).  The value of $eip will be the
   next instruction.
   If we continue the process using PTRACE_CONT, we will get a
   SIGTRAP when we hit a breakpoint.  The value of $eip will be
   the instruction after the breakpoint (i.e. needs to be
   decremented).  If we report the SIGTRAP to GDB, we must also
   report the undecremented PC.  If we cancel the SIGTRAP, we
   must resume at the decremented PC.

   (Presumably, not yet tested) On a non-decr_pc_after_break machine
   with hardware or kernel single-step:
   If we single-step over a breakpoint instruction, our PC will
   point at the following instruction.  If we continue and hit a
   breakpoint instruction, our PC will point at the breakpoint
   instruction.  */
static CORE_ADDR
get_stop_pc (void)
{
  CORE_ADDR stop_pc = (*the_low_target.get_pc) ();

  if (get_thread_process (current_inferior)->stepping)
    return stop_pc;
  else
    return stop_pc - the_low_target.decr_pc_after_break;
}

static void *
add_process (int pid, long tid)
{
  struct process_info *process;

  process = (struct process_info *) malloc (sizeof (*process));
  memset (process, 0, sizeof (*process));

  process->head.id = pid;

  process->tid = tid;
  process->lwpid = tid;

  add_inferior_to_list (&all_processes, &process->head);

  return process;
}

/* Start an inferior process and returns its pid.
   ALLARGS is a vector of program-name and args. */

static int
linux_create_inferior (char *program, char **allargs)
{

  fprintf (stderr, "Cannot exec %s: %s.\n", program,
	   strerror (errno));
  fflush (stderr);
  _exit (0177);
  /* NOT REACHED */
  return -1;
}

int
linux_attach (int domid)
{
    struct process_info *new_process;
    current_domid = domid;
    /* this is handled for all active vcpus in PTRACE_ATTACH via the thread_create_callback */
    new_process = (struct process_info *) add_process (domid, curvcpuid());
    /* Don't ignore the initial SIGSTOP if we just attached to this process.  */
    /* vcpuid == 0 */
    add_thread (0, new_process);
    new_process->stop_expected = 0;

    if (xc_ptrace (xc_handle, PTRACE_ATTACH, domid, 0, isfile) != 0) {
	fprintf (stderr, "Cannot attach to domain %d: %s (%d)\n", domid,
		 strerror (errno), errno);
	fflush (stderr);
	if (!using_threads)
	    _exit (0177);
    }

    return 0;
}

/* Kill the inferior process.  Make us have no inferior.  */

static void
linux_kill_one_process (struct inferior_list_entry *entry)
{
  struct thread_info *thread = (struct thread_info *) entry;
  struct process_info *process = get_thread_process (thread);
  xc_ptrace (xc_handle, PTRACE_KILL, pid_of (process), 0, 0);
}


static void
linux_kill (void)
{
  for_each_inferior (&all_threads, linux_kill_one_process);
}

static void
linux_detach_one_process (struct inferior_list_entry *entry)
{

  xc_ptrace (xc_handle, PTRACE_DETACH, current_domid, 0, 0);
}


static void
linux_detach (void)
{
  for_each_inferior (&all_threads, linux_detach_one_process);
}

/* Return nonzero if the given thread is still alive.  */
static int
linux_thread_alive (int tid)
{
    if (find_inferior_id (&all_threads, tid) != NULL)
	return 1;
    else
	return 0;
}

/* Wait for process, returns status.  */

static unsigned char
linux_wait (char *status)
{
  int w;
  if (xc_waitdomain(xc_handle, current_domid, &w, 0))
      return -1;
  
  *status = 'T';
  if (expect_signal)
      return expect_signal;
  else
      return SIGTRAP;

}

static void
linux_resume (struct thread_resume *resume_info)
{
  int step = resume_info->step;
  TRACE_ENTER;
  expect_signal = resume_info->sig;
  for_each_inferior(&all_threads, regcache_invalidate_one);
  if (debug_threads)
    fprintf(stderr, "step: %d\n", step);
  xc_ptrace (xc_handle, step ? PTRACE_SINGLESTEP : PTRACE_CONT, 
	    resume_info->thread, 0, 0);

}


static int
regsets_fetch_inferior_registers ()
{
  struct regset_info *regset;
  TRACE_ENTER;
  regset = target_regsets;

  while (regset->size >= 0)
    {
      void *buf;
      int res;

      if (regset->size == 0)
	{
	  regset ++;
	  continue;
	}

      buf = malloc (regset->size);
      res = xc_ptrace (xc_handle, regset->get_request, 
		      curvcpuid(),
		      0, (PTRACE_XFER_TYPE)buf);
      if (res < 0)
	{
	  if (errno == EIO)
	    {
	      /* If we get EIO on the first regset, do not try regsets again.
		 If we get EIO on a later regset, disable that regset.  */
	      if (regset == target_regsets)
		{
		  use_regsets_p = 0;
		  return -1;
		}
	      else
		{
		  regset->size = 0;
		  continue;
		}
	    }
	  else
	    {
	      char s[256];
	      sprintf (s, "ptrace(regsets_fetch_inferior_registers) PID=%d",
		       inferior_pid);
	      perror (s);
	    }
	}
      regset->store_function (buf);
      regset ++;
    }
  return 0;
}

static int
regsets_store_inferior_registers ()
{
  struct regset_info *regset;
  TRACE_ENTER;
  regset = target_regsets;

  while (regset->size >= 0)
    {
      void *buf;
      int res;

      if (regset->size == 0)
	{
	  regset ++;
	  continue;
	}

      buf = malloc (regset->size);
      regset->fill_function (buf);
      res = xc_ptrace (xc_handle, regset->set_request, curvcpuid(), 0, (PTRACE_XFER_TYPE)buf);
      if (res < 0)
	{
	  if (errno == EIO)
	    {
	      /* If we get EIO on the first regset, do not try regsets again.
		 If we get EIO on a later regset, disable that regset.  */
	      if (regset == target_regsets)
		{
		  use_regsets_p = 0;
		  return -1;
		}
	      else
		{
		  regset->size = 0;
		  continue;
		}
	    }
	  else
	    {
#ifdef DEBUG
	      perror ("Warning: ptrace(regsets_store_inferior_registers)");
#endif
	    }
	}
      regset ++;
      free (buf);
    }
  return 0;
}




void
linux_fetch_registers (int regno)
{
  if (use_regsets_p)
    {
      if (regsets_fetch_inferior_registers () == 0)
	return;
    }

}

void
linux_store_registers (int regno)
{
  if (use_regsets_p)
    {
      if (regsets_store_inferior_registers () == 0)
	return;
    }
}


/* Copy LEN bytes from inferior's memory starting at MEMADDR
   to debugger memory starting at MYADDR.  */

static int
linux_read_memory (CORE_ADDR memaddr, char *myaddr, int len)
{
  register int i;
  /* Round starting address down to longword boundary.  */
  register CORE_ADDR addr = memaddr & -(CORE_ADDR) sizeof (PTRACE_XFER_TYPE);
  /* Round ending address up; get number of longwords that makes.  */
  register int count
    = (((memaddr + len) - addr) + sizeof (PTRACE_XFER_TYPE) - 1)
      / sizeof (PTRACE_XFER_TYPE);
  /* Allocate buffer of that many longwords.  */
  register PTRACE_XFER_TYPE *buffer
    = (PTRACE_XFER_TYPE *) alloca (count * sizeof (PTRACE_XFER_TYPE));

  TRACE_ENTER;
  /* Read all the longwords */
  for (i = 0; i < count; i++, addr += sizeof (PTRACE_XFER_TYPE))
    {
      errno = 0;
      buffer[i] = xc_ptrace (xc_handle, PTRACE_PEEKTEXT, curvcpuid(), (PTRACE_ARG3_TYPE) addr, 0);
      if (errno)
	return errno;
    }

  /* Copy appropriate bytes out of the buffer.  */
  memcpy (myaddr, (char *) buffer + (memaddr & (sizeof (PTRACE_XFER_TYPE) - 1)), len);

  return 0;
}

/* Copy LEN bytes of data from debugger memory at MYADDR
   to inferior's memory at MEMADDR.
   On failure (cannot write the inferior)
   returns the value of errno.  */

static int
linux_write_memory (CORE_ADDR memaddr, const char *myaddr, int len)
{
  register int i;
  /* Round starting address down to longword boundary.  */
  register CORE_ADDR addr = memaddr & -(CORE_ADDR) sizeof (PTRACE_XFER_TYPE);
  /* Round ending address up; get number of longwords that makes.  */
  register int count
  = (((memaddr + len) - addr) + sizeof (PTRACE_XFER_TYPE) - 1) / sizeof (PTRACE_XFER_TYPE);
  /* Allocate buffer of that many longwords.  */
  register PTRACE_XFER_TYPE *buffer = (PTRACE_XFER_TYPE *) alloca (count * sizeof (PTRACE_XFER_TYPE));
  extern int errno;

  TRACE_ENTER;

  /* Fill start and end extra bytes of buffer with existing memory data.  */

  buffer[0] = xc_ptrace (xc_handle, PTRACE_PEEKTEXT, curvcpuid(),
		      (PTRACE_ARG3_TYPE) addr, 0);

  if (count > 1)
    {
      buffer[count - 1]
	= xc_ptrace (xc_handle, PTRACE_PEEKTEXT, curvcpuid(),
		  (PTRACE_ARG3_TYPE) (addr + (count - 1)
				      * sizeof (PTRACE_XFER_TYPE)),
		  0);
    }

  /* Copy data to be written over corresponding part of buffer */

  memcpy ((char *) buffer + (memaddr & (sizeof (PTRACE_XFER_TYPE) - 1)), myaddr, len);

  /* Write the entire buffer.  */
  for (i = 0; i < count; i++, addr += sizeof (PTRACE_XFER_TYPE))
    {
      errno = 0;
      xc_ptrace (xc_handle, PTRACE_POKETEXT, curvcpuid(), 
		(PTRACE_ARG3_TYPE) addr, buffer[i]);
      if (errno)
	return errno;
    }

  return 0;
}

static void
linux_look_up_symbols (void)
{
  if (using_threads) 
    return;

  using_threads = thread_db_init ();

}

static void
linux_send_signal (int signum)
{
  extern int signal_pid;

  TRACE_ENTER;
  signal_to_send = signum;
  psignal(signum, "need to send ");
  if (cont_thread > 0)
    {
      struct process_info *process;

      process = get_thread_process (current_inferior);
      kill (process->lwpid, signum);
    }
  else
    kill (signal_pid, signum);
}

/* Copy LEN bytes from inferior's auxiliary vector starting at OFFSET
   to debugger memory starting at MYADDR.  */

static int
linux_read_auxv (CORE_ADDR offset, char *myaddr, unsigned int len)
{
  char filename[PATH_MAX];
  int fd, n;

  TRACE_ENTER;
  snprintf (filename, sizeof filename, "/proc/%d/auxv", inferior_pid);

  fd = open (filename, O_RDONLY);
  if (fd < 0)
    return -1;

  if (offset != (CORE_ADDR) 0
      && lseek (fd, (off_t) offset, SEEK_SET) != (off_t) offset)
    n = -1;
  else
    n = read (fd, myaddr, len);

  close (fd);

  return n;
}


static struct target_ops linux_xen_target_ops = {
  linux_create_inferior,
  linux_attach,
  linux_kill,
  linux_detach,
  linux_thread_alive,
  linux_resume,
  linux_wait,
  linux_fetch_registers,
  linux_store_registers,
  linux_read_memory,
  linux_write_memory,
  linux_look_up_symbols,
  linux_send_signal,
  linux_read_auxv,
};

static void
linux_init_signals ()
{
  /* FIXME drow/2002-06-09: As above, we should check with LinuxThreads
     to find what the cancel signal actually is.  */
  signal (__SIGRTMIN+1, SIG_IGN);
}

void
initialize_low (void)
{
  using_threads = 0;
  xc_handle = xc_interface_open();
  set_target_ops (&linux_xen_target_ops);
  set_breakpoint_data (the_low_target.breakpoint,
		       the_low_target.breakpoint_len);
  init_registers ();
  linux_init_signals ();
  using_threads = thread_db_init ();

}


static void
thread_create_callback(long vcpuid)
{
  struct thread_info *inferior;
  struct process_info *process;

  /*  If we are attaching to our first thread, things are a little
   *  different.  
   */
  if (all_threads.head == all_threads.tail)
    {
      inferior = (struct thread_info *) all_threads.head;
      process = get_thread_process (inferior);
      if (process->thread_known == 0)
	{
	  /* Switch to indexing the threads list by TID.  */
	  change_inferior_id (&all_threads, vcpuid);
	  goto found;
	}
    }
  if (debug_threads)
    fprintf (stderr, "looking up thread %ld\n",
	     vcpuid);
  inferior = (struct thread_info *) find_inferior_id (&all_threads,
						      vcpuid);
  /* if vcpu alread registered - do nothing */
  if (inferior != NULL) 
    return;

  if (debug_threads)
    fprintf (stderr, "Attaching to thread %ld\n",
	     vcpuid);

  process = add_process(current_domid, vcpuid);

  add_thread(vcpuid, process);
  inferior = (struct thread_info *) find_inferior_id (&all_threads,
						      vcpuid);
  if (inferior == NULL)
    {
      warning ("Could not attach to thread %ld\n",
	       vcpuid);
      return;
    }


found:
  if (debug_threads)
    fprintf (stderr, "notifying of new thread %ld\n",
	     vcpuid);
  new_thread_notify (vcpuid);

  process->tid = vcpuid;
  process->lwpid = vcpuid;

  process->thread_known = 1;
}

static void
thread_death_callback(long vcpuid)
{
    if (debug_threads)
      fprintf (stderr, "Buuurp...! CPU down event.\n");
}

int
thread_db_init(void)
{
  debug_threads = 0;
  xc_register_event_handler(thread_create_callback, TD_CREATE);
  xc_register_event_handler(thread_death_callback, TD_DEATH);
  return 1;
}

/* XXX GAG ME */
static int breakpoint_found;
static void
set_breakpoint_inferior (struct inferior_list_entry *entry)
{
  struct thread_info *thread = (struct thread_info *) entry;
  struct thread_info *saved_inferior = current_inferior;
  CORE_ADDR eip;
  unsigned char buf[2] = {0, 0};
  current_inferior = thread;
  if (!breakpoint_found) {
    eip = get_stop_pc();
    linux_read_memory(eip, buf, 1);
    if (buf[0] == 0xcc) {
      breakpoint_found = 1;
      return;
    }
  } else if (breakpoint_found == 2) {
    if (get_thread_process (current_inferior)->stepping) {
      printf("stepping\n");
      breakpoint_found = 1;
      return;
    } 
  }
  current_inferior = saved_inferior;


}

static void
linux_set_inferior (void)
{
  breakpoint_found = 0;
  for_each_inferior (&all_threads, set_breakpoint_inferior);
  if (!breakpoint_found) {
    breakpoint_found = 2;
    for_each_inferior (&all_threads, set_breakpoint_inferior);
  }
}

