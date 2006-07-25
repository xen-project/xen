/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include "ofh.h"

/*
 * These are ISA independent OF services
 */

struct ofh_srvc ofh_srvc[] = {
    /* Document Section 6.3.2.1 Client Interface */
    { .ofs_name = "test", .ofs_func = ((ofh_func_t *)~0UL) },
    { .ofs_name = "test-method", .ofs_func = ofh_test_method },

    /* Document Section 6.3.2.2 Device Tree */
    { .ofs_name = "peer", .ofs_func = ofh_peer },
    { .ofs_name = "child", .ofs_func = ofh_child },
    { .ofs_name = "parent", .ofs_func = ofh_parent },
    { .ofs_name = "instance-to-package",
      .ofs_func = ofh_instance_to_package },
    { .ofs_name = "getproplen", .ofs_func = ofh_getproplen },
    { .ofs_name = "getprop", .ofs_func = ofh_getprop },
    { .ofs_name = "nextprop", .ofs_func = ofh_nextprop },
    { .ofs_name = "setprop", .ofs_func = ofh_setprop },
    { .ofs_name = "canon", .ofs_func = ofh_canon },
    { .ofs_name = "finddevice", .ofs_func = ofh_finddevice },
    { .ofs_name = "instance-to-path", .ofs_func = ofh_instance_to_path },
    { .ofs_name = "package-to-path", .ofs_func = ofh_package_to_path },
    { .ofs_name = "call-method", .ofs_func = ofh_call_method },

    /* Document Section 6.3.2.3 Device I/O */
    { .ofs_name = "open", .ofs_func = ofh_open },
    { .ofs_name = "close", .ofs_func = ofh_close },
    { .ofs_name = "read", .ofs_func = ofh_read },
    { .ofs_name = "write", .ofs_func = ofh_write },
    { .ofs_name = "seek", .ofs_func = ofh_seek },

    /* Document Section 6.3.2.4 Memory */
    { .ofs_name = "claim", .ofs_func = ofh_claim },
    { .ofs_name = "release", .ofs_func = ofh_release },

    /* Document Section 6.3.2.5 Control Transfer */
    { .ofs_name = "boot", .ofs_func = ofh_boot },
    { .ofs_name = "enter", .ofs_func = ofh_enter },
    { .ofs_name = "exit", .ofs_func = ofh_exit },
    { .ofs_name = "chain", .ofs_func = ofh_chain },
    { .ofs_name = "quiesce", .ofs_func = ofh_quiesce },

    /* Document Section 6.3.2.6 User Interface */
    { .ofs_name = "interpret", .ofs_func = ofh_nosup },
    { .ofs_name = "set-callback", .ofs_func = ofh_nosup },
    { .ofs_name = "set-symbol-lookup", .ofs_func = ofh_nosup },

    /* Document Section 6.3.2.7 Time */
    { .ofs_name = "milliseconds", .ofs_func = ofh_nosup },
    { .ofs_name = NULL, .ofs_func = NULL}
};

/*
 * These are services particular to poweprc 32/64
 */

struct ofh_srvc ofh_isa_srvc[] = {
    /* Document Section 8.5.1 Real-Mode physical memory ... */
    { .ofs_name = "alloc-real_mem", .ofs_func = ofh_nosup },

    /* Document Section 8.5.2 Virtual address translation ... */
    { .ofs_name = "map", .ofs_func = ofh_nosup },
    { .ofs_name = "unmap", .ofs_func = ofh_nosup },
    { .ofs_name = "translate", .ofs_func = ofh_nosup },

    /* Document Section 11.3 Client Interface Services */
    { .ofs_name = "start-cpu", .ofs_func = ofh_start_cpu },
    { .ofs_name = "stop-self", .ofs_func = ofh_stop_self },
    { .ofs_name = "idle-self", .ofs_func = ofh_idle_self },
    { .ofs_name = "resume-cpu", .ofs_func = ofh_resume_cpu },
    { .ofs_name = NULL, .ofs_func = NULL}
};

