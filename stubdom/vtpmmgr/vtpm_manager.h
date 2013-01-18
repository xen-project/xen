/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef VTPM_MANAGER_H
#define VTPM_MANAGER_H

#define VTPM_TAG_REQ 0x01c1
#define VTPM_TAG_RSP 0x01c4
#define COMMAND_BUFFER_SIZE 4096

// Header size
#define VTPM_COMMAND_HEADER_SIZE ( 2 + 4 + 4)

//************************ Command Codes ****************************
#define VTPM_ORD_BASE       0x0000
#define VTPM_PRIV_MASK      0x01000000 // Priviledged VTPM Command
#define VTPM_PRIV_BASE      (VTPM_ORD_BASE | VTPM_PRIV_MASK)

// Non-priviledged VTPM Commands (From DMI's)
#define VTPM_ORD_SAVEHASHKEY      (VTPM_ORD_BASE + 1) // DMI requests encryption key for persistent storage
#define VTPM_ORD_LOADHASHKEY      (VTPM_ORD_BASE + 2) // DMI requests symkey to be regenerated

//************************ Return Codes ****************************
#define VTPM_SUCCESS               0
#define VTPM_FAIL                  1
#define VTPM_UNSUPPORTED           2
#define VTPM_FORBIDDEN             3
#define VTPM_RESTORE_CONTEXT_FAILED    4
#define VTPM_INVALID_REQUEST       5

#endif
