/******************************************************************************
 * panic.c
 *
 * Displays a register dump and stack trace for debugging.
 *
 * Copyright (c) 2014, Thomas Leonard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <mini-os/os.h>
#include <mini-os/console.h>
#include <arch_mm.h>

extern int irqstack[];
extern int irqstack_end[];

typedef void handler(void);

extern handler fault_reset;
extern handler fault_undefined_instruction;
extern handler fault_svc;
extern handler fault_prefetch_call;
extern handler fault_prefetch_abort;
extern handler fault_data_abort;

void dump_registers(int *saved_registers) {
    static int in_dump = 0;
    int *sp, *stack_top, *x;
    char *fault_name;
    void *fault_handler;
    int i;

    if (in_dump)
    {
        printk("Crash while in dump_registers! Not generating a second report.\n");
        return;
    }

    in_dump = 1;

    fault_handler = (handler *) saved_registers[17];
    if (fault_handler == fault_reset)
        fault_name = "reset";
    else if (fault_handler == fault_undefined_instruction)
        fault_name = "undefined_instruction";
    else if (fault_handler == fault_svc)
        fault_name = "svc";
    else if (fault_handler == fault_prefetch_call)
        fault_name = "prefetch_call";
    else if (fault_handler == fault_prefetch_abort)
        fault_name = "prefetch_abort";
    else if (fault_handler == fault_data_abort)
        fault_name = "data_abort";
    else
        fault_name = "unknown fault type!";

    printk("Fault handler at %p called (%s)\n", fault_handler, fault_name);

    for (i = 0; i < 16; i++) {
        printk("r%d = %x\n", i, saved_registers[i]);
    }
    printk("CPSR = %x\n", saved_registers[16]);

    printk("Stack dump (innermost last)\n");
    sp = (int *) saved_registers[13];

    if (sp >= _boot_stack && sp <= _boot_stack_end)
        stack_top = _boot_stack_end;                    /* The boot stack */
    else if (sp >= irqstack && sp <= irqstack_end)
        stack_top = irqstack_end;                       /* The IRQ stack */
    else
        stack_top = (int *) ((((unsigned long) sp) | (__STACK_SIZE-1)) + 1);        /* A normal thread stack */

    for (x = stack_top - 1; x >= sp; x--)
    {
        printk("  [%8p] %8x\n", x, *x);
    }
    printk("End of stack\n");

    in_dump = 0;
}
