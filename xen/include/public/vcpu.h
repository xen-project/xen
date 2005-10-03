/******************************************************************************
 * vcpu.h
 * 
 * VCPU creation and hotplug.
 * 
 * Copyright (c) 2005, Keir Fraser <keir@xensource.com>
 */

#ifndef __XEN_PUBLIC_VCPU_H__
#define __XEN_PUBLIC_VCPU_H__

/*
 * Prototype for this hypercall is:
 *  int vcpu_op(int cmd, int vcpuid, void *extra_args)
 * @cmd        == VCPUOP_??? (VCPU operation).
 * @vcpuid     == VCPU to operate on.
 * @extra_args == Operation-specific extra arguments (NULL if none).
 */

/*
 * Create a new VCPU. This must be called before a VCPU can be referred to
 * in any other hypercall (e.g., to bind event channels). The new VCPU
 * will not run until it is brought up by VCPUOP_up.
 * 
 * @extra_arg == pointer to vcpu_guest_context structure containing initial
 *               state for the new VCPU.
 */
#define VCPUOP_create               0

/*
 * Bring up a newly-created or previously brought-down VCPU. This makes the
 * VCPU runnable.
 */
#define VCPUOP_up                   1

/*
 * Bring down a VCPU (i.e., make it non-runnable).
 * There are a few caveats that callers should observe:
 *  1. This operation may return, and VCPU_is_up may return false, before the
 *     VCPU stops running (i.e., the command is asynchronous). It is a good
 *     idea to ensure that the VCPU has entered a non-critical loop before
 *     bringing it down. Alternatively, this operation is guaranteed
 *     synchronous if invoked by the VCPU itself.
 *  2. After a VCPU is created, there is currently no way to drop all its
 *     references to domain memory. Even a VCPU that is down still holds
 *     memory references via its pagetable base pointer and GDT. It is good
 *     practise to move a VCPU onto an 'idle' or default page table, LDT and
 *     GDT before bringing it down.
 */
#define VCPUOP_down                 2

/* Returns 1 if the given VCPU is up. */
#define VCPUOP_is_up                3

#endif /* __XEN_PUBLIC_VCPU_H__ */
