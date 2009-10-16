#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (c) 2005 XenSource Ltd.
#============================================================================

"""Domain migration.
"""

import sys

from xen.xm.opts import *

from main import server, serverType, get_single_vm, SERVER_XEN_API

gopts = Opts(use="""[options] DOM HOST

Migrate domain DOM to host HOST.
Xend must be running on the local host and on HOST.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

gopts.opt('live', short='l',
          fn=set_true, default=0,
          use="Use live migration.")

gopts.opt('port', short='p', val='portnum',
          fn=set_int, default=0,
          use="Use specified port for migration.")

gopts.opt('node', short='n', val='nodenum',
          fn=set_int, default=-1,
          use="Use specified NUMA node on target.")

gopts.opt('ssl', short='s',
          fn=set_true, default=None,
          use="Use ssl connection for migration.")

gopts.opt('change_home_server', short='c',
          fn=set_true, default=0,
          use="Change home server for managed domains.")

def help():
    return str(gopts)
    
def main(argv):
    opts = gopts
    opts.reset()
    args = opts.parse(argv)
    
    if len(args) != 2:
        raise OptionError('Invalid number of arguments')

    dom = args[0]
    dst = args[1]

    if serverType == SERVER_XEN_API:
        vm_ref = get_single_vm(dom)
        other_config = {
            "port":     opts.vals.port,
            "node":     opts.vals.node,
            "ssl":      opts.vals.ssl,
            "change_home_server": opts.vals.change_home_server
            }
        server.xenapi.VM.migrate(vm_ref, dst, bool(opts.vals.live),
                                 other_config)
    else:
        server.xend.domain.migrate(dom, dst, opts.vals.live,
                                   opts.vals.port,
                                   opts.vals.node,
                                   opts.vals.ssl,
                                   opts.vals.change_home_server)
