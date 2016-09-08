/*
 * Copyright (c) 2007, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define DEFAULT_LEASE_TIME_SECS 30

int lock(char *fn_to_lock, char *uuid, int force, int readonly, int *lease_time, int *retstat);
int unlock(char *fn_to_unlock, char *uuid, int readonly, int *retstat);
int lock_delta(char *fn_to_check, int *cur_lease_time, int *max_lease_time);

typedef enum {
    LOCK_OK          =  0,
    LOCK_EBADPARM    = -1,
    LOCK_ENOMEM      = -2,
    LOCK_ESTAT       = -3,
    LOCK_EHELD_WR    = -4,
    LOCK_EHELD_RD    = -5,
    LOCK_EOPEN       = -6,
    LOCK_EXLOCK_OPEN = -7,
    LOCK_EXLOCK_WRITE= -8,
    LOCK_EINODE      = -9,
    LOCK_EUPDATE     = -10,
    LOCK_EREAD       = -11,
    LOCK_EREMOVE     = -12,
    LOCK_ENOLOCK     = -13,
    LOCK_EUSAGE      = -14,
} lock_error;
