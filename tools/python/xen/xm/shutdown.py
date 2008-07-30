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
#============================================================================

"""Domain shutdown.
"""
import time

from xen.xend import sxp
from opts import *
from main import server, serverType, SERVER_XEN_API, get_single_vm
from xen.xend.XendAPIConstants import *

RECREATING_TIMEOUT = 30

gopts = Opts(use="""[options] [DOM]

Shutdown one or more domains gracefully.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

gopts.opt('all', short='a',
         fn=set_true, default=0,
         use="Shutdown all domains.")

gopts.opt('wait', short='w',
         fn=set_true, default=0,
         use='Wait for shutdown to complete.')

gopts.opt('halt', short='H',
          fn=set_true, default=0,
          use='Shutdown without reboot.')

gopts.opt('reboot', short='R',
          fn=set_true, default=0,
          use='Shutdown and reboot.')

def wait_reboot(opts, doms, rcs):
    if serverType == SERVER_XEN_API:
        opts.err("Cannot wait for reboot w/ XenAPI (yet)")

    recreating = {}
    while doms:
        alive = server.xend.domains(0)
        reboot = []
        for d in doms:
            if d in alive:
                rc = server.xend.domain.getRestartCount(d)
                if rc == rcs[d]: continue
                reboot.append(d)

            # Probably the domain is being recreated now.
            # We have to wait just a bit for recreating the domain.
            elif not recreating.has_key(d):
                recreating[d] = 0
            else:
                recreating[d] += 1
                if recreating[d] > RECREATING_TIMEOUT:
                    opts.info("Domain %s destroyed for failing to reboot" % d)
                    doms.remove(d)

        for d in reboot:
            opts.info("Domain %s rebooted" % d)
            doms.remove(d)
        time.sleep(1)
    opts.info("All domains rebooted")

def wait_shutdown(opts, doms):
    while doms:
        if serverType == SERVER_XEN_API:
            alive = [dom for dom in server.xenapi.VM.get_all()
                     if server.xenapi.VM.get_power_state(dom) ==
                     XEN_API_VM_POWER_STATE[XEN_API_VM_POWER_STATE_RUNNING]]
        else:
            alive = server.xend.domains(0)
        dead = []
        for d in doms:
            if d in alive: continue
            dead.append(d)
        for d in dead:
            opts.info("Domain %s terminated" % d)
            doms.remove(d)
        time.sleep(1)
    opts.info("All domains terminated")

def shutdown(opts, doms, mode, wait):
    rcs = {}
    for d in doms:
        if serverType == SERVER_XEN_API:
            if mode == 'halt':
                server.xenapi.VM.clean_shutdown(d)
            if mode == 'reboot':
                server.xenapi.VM.clean_reboot(d)
            if mode == 'poweroff':
                server.xenapi.VM.clean_shutdown(d)
        else:
            rcs[d] = server.xend.domain.getRestartCount(d)
            server.xend.domain.shutdown(d, mode)

    if wait:
        if mode == 'reboot':
            wait_reboot(opts, doms, rcs)
        else:
            wait_shutdown(opts, doms)

def shutdown_mode(opts):
    if opts.vals.halt and opts.vals.reboot:
        opts.err("Can't specify halt and reboot")

    if opts.vals.halt:
        return 'halt'
    elif opts.vals.reboot:
        return 'reboot'
    else:
        return 'poweroff'

def main_all(opts, args):
    if serverType == SERVER_XEN_API:
        doms = [dom for dom in server.xenapi.VM.get_all()
                if not server.xenapi.VM.get_is_control_domain(dom)]
    else:
        doms = server.xend.domains(0)
        dom0_name = sxp.child_value(server.xend.domain(0), 'name')
        doms.remove(dom0_name)
    mode = shutdown_mode(opts)  
    shutdown(opts, doms, mode, opts.vals.wait)

def main_dom(opts, args):
    if len(args) == 0: opts.err('No domain parameter given')
    if len(args) >  1: opts.err('No multiple domain parameters allowed')
    if serverType == SERVER_XEN_API:
        dom = get_single_vm(args[0])
    else:
        dom = sxp.child_value(server.xend.domain(args[0]), 'name')
    mode = shutdown_mode(opts)  
    shutdown(opts, [ dom ], mode, opts.vals.wait)
    
def main(argv):
    opts = gopts
    opts.reset()
    args = opts.parse(argv)
    if opts.vals.help:
        return
    if opts.vals.all:
        main_all(opts, args)
    else:
        main_dom(opts, args)
        
