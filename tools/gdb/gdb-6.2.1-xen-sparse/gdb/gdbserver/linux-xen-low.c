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

#define TRACE_ENTER /* printf("enter %s\n", __FUNCTION__) */
#define ptrace xc_ptrace
long xc_ptrace(enum __ptrace_request request, ...);

int waitdomain(int domain, int *status, int options);

#define DOMFLAGS_DYING     (1<<0) /* Domain is scheduled to die.             */
#define DOMFLAGS_CRASHED   (1<<1) /* Crashed domain; frozen for postmortem.  */
#define DOMFLAGS_SHUTDOWN  (1<<2) /* The guest OS has shut itself down.      */
#define DOMFLAGS_PAUSED    (1<<3) /* Currently paused by control software.   */
#define DOMFLAGS_BLOCKED   (1<<4) /* Currently blocked pending an event.     */
#define DOMFLAGS_RUNNING   (1<<5) /* Domain is currently running.            */



struct inferior_list all_processes;


static int current_domain;
static int expect_signal = 0;
static int signal_to_send = 0; 
static void linux_resume (struct thread_resume *resume_info);

int debug_threads;
int using_threads;
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
#if 0
static CORE_ADDR
get_stop_pc (void)
{
  CORE_ADDR stop_pc = (*the_low_target.get_pc) ();

  if (get_thread_process (current_inferior)->stepping)
    return stop_pc;
  else
    return stop_pc - the_low_target.decr_pc_after_break;
}
#endif
static void *
add_process (int pid)
{
  struct process_info *process;

  process = (struct process_info *) malloc (sizeof (*process));
  memset (process, 0, sizeof (*process));

  process->head.id = pid;

  /* Default to tid == lwpid == pid.  */
  process->tid = pid;
  process->lwpid = pid;

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
linux_attach (int domain)
{
    struct process_info *new_process;
    current_domain = domain;
    if (ptrace (PTRACE_ATTACH, domain, 0, 0) != 0) {
	fprintf (stderr, "Cannot attach to domain %d: %s (%d)\n", domain,
		 strerror (errno), errno);
	fflush (stderr);
	_exit (0177);
    }
    
    new_process = (struct process_info *) add_process (domain);
    add_thread (domain, new_process);

    /* Don't ignore the initial SIGSTOP if we just attached to this process.  */
    new_process->stop_expected = 0;
    
    return 0;
}

/* Kill the inferior process.  Make us have no inferior.  */

static void
linux_kill_one_process (struct inferior_list_entry *entry)
{
  struct thread_info *thread = (struct thread_info *) entry;
  struct process_info *process = get_thread_process (thread);
  ptrace (PTRACE_KILL, pid_of (process), 0, 0);

}

static void
linux_kill (void)
{
  for_each_inferior (&all_threads, linux_kill_one_process);
}


static void
linux_detach_one_process (struct inferior_list_entry *entry)
{
  struct thread_info *thread = (struct thread_info *) entry;
  struct process_info *process = get_thread_process (thread);

  ptrace (PTRACE_DETACH, pid_of (process), 0, 0);
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
  TRACE_ENTER;
  if (waitdomain(current_domain, &w, 0))
      return -1;
  
  if (w & (DOMFLAGS_CRASHED|DOMFLAGS_DYING)) {
      *status = 'W';
      return 0;
  }


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

  ptrace (step ? PTRACE_SINGLESTEP : PTRACE_CONT, current_domain, 0, 0);

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
      res = ptrace (regset->get_request, inferior_pid, 0, buf);
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
      res = ptrace (regset->set_request, inferior_pid, 0, buf);
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
	      perror ("Warning: ptrace(regsets_store_inferior_registers)");
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
    printf("store %d\n", regno);
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
      buffer[i] = ptrace (PTRACE_PEEKTEXT, inferior_pid, (PTRACE_ARG3_TYPE) addr, 0);
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

  buffer[0] = ptrace (PTRACE_PEEKTEXT, inferior_pid,
		      (PTRACE_ARG3_TYPE) addr, 0);

  if (count > 1)
    {
      buffer[count - 1]
	= ptrace (PTRACE_PEEKTEXT, inferior_pid,
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
      ptrace (PTRACE_POKETEXT, inferior_pid, (PTRACE_ARG3_TYPE) addr, buffer[i]);
      if (errno)
	return errno;
    }

  return 0;
}

static void
linux_look_up_symbols (void)
{
#if 0
  using_threads = thread_db_init ();
#endif
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

  set_target_ops (&linux_xen_target_ops);
  set_breakpoint_data (the_low_target.breakpoint,
		       the_low_target.breakpoint_len);
  init_registers ();
  linux_init_signals ();
}
