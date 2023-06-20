/* SPDX-License-Identifier: GPL-2.0-or-later */

    .section .text.header, "ax", %progbits

ENTRY(start)
    /*
     * Depending on how we were booted, the CPU could be running in either
     * Little Endian or Big Endian mode. The following trampoline from Linux
     * cleverly uses an instruction that encodes to a NOP if the CPU's
     * endianness matches the assumption of the assembler (LE, in our case)
     * or a branch to code that performs the endian switch in the other case.
     */
    tdi 0, 0, 0x48    /* Reverse endian of b . + 8          */
    b . + 44          /* Skip trampoline if endian is good  */
    .long 0xa600607d  /* mfmsr r11                          */
    .long 0x01006b69  /* xori r11,r11,1                     */
    .long 0x00004039  /* li r10,0                           */
    .long 0x6401417d  /* mtmsrd r10,1                       */
    .long 0x05009f42  /* bcl 20,31,$+4                      */
    .long 0xa602487d  /* mflr r10                           */
    .long 0x14004a39  /* addi r10,r10,20                    */
    .long 0xa6035a7d  /* mtsrr0 r10                         */
    .long 0xa6037b7d  /* mtsrr1 r11                         */
    .long 0x2400004c  /* rfid                               */

    /* Now that the endianness is confirmed, continue */
1:  b 1b

    .size start, . - start
    .type start, %function
