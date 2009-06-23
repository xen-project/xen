/* Copyright (c) 2008, XenSource Inc.
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
#ifndef __BLKTAP2_UUID_H__
#define __BLKTAP2_UUID_H__

#if defined(__linux__) || defined(__Linux__)

#include <uuid/uuid.h>

#else

#include <inttypes.h>
#include <string.h>
#include <uuid.h>

static inline int uuid_is_null(uuid_t uuid)
{
    uint32_t status;
    return uuid_is_nil(&uuid, &status);
}

static inline void uuid_generate(uuid_t uuid)
{
    uint32_t status;
    uuid_create(&uuid, &status);
}

static inline void uuid_unparse(uuid_t uuid, char *out)
{
    uint32_t status;
    uuid_to_string(&uuid, (char **)&out, &status);
}

static inline void uuid_copy(uuid_t dst, uuid_t src)
{
    memcpy(dst, src, sizeof(dst));
}

static inline void uuid_clear(uuid_t uu)
{
    memset(uu, 0, sizeof(uu));
}

#define uuid_compare(x,y) \
    ({ uint32_t status; uuid_compare(&(x),&(y),&status); })

#endif

#endif /* __BLKTAP2_UUID_H__ */
