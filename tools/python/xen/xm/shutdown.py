# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Domain shutdown.
"""
import string
import sys
import time

from xen.xend.XendClient import server
from xen.xm.opts import *

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

def shutdown(opts, doms, mode, wait):
    def domains():
        return [ int(a) for a in server.xend_domains() ]
    if doms == None: doms = domains()
    if 0 in doms:
        doms.remove(0)
    for d in doms:
        server.xend_domain_shutdown(d, mode)
    if wait:
        while doms:
            alive = domains()
            dead = []
            for d in doms:
                if d in alive: continue
                dead.append(d)
            for d in dead:
                opts.info("Domain %d terminated" % d)
                doms.remove(d)
            time.sleep(1)
        opts.info("All domains terminated")

def shutdown_mode(opts):
    mode = 'poweroff'
    if opts.vals.wait:
        mode = 'halt'
        if opts.vals.reboot:
           opts.err("Can't specify wait and reboot") 
    else:
        if opts.vals.halt and opts.vals.reboot:
            opts.err("Can't specify halt and reboot")
        if opts.vals.halt:
            mode = 'halt'
        elif opts.vals.reboot:
            mode = 'reboot'
    return mode

def main_all(opts, args):
    shutdown(opts, None, opts.vals.wait)

def main_dom(opts, args):
    if len(args) < 1: opts.err('Missing domain')
    dom = args[0]
    try:
        domid = int(dom)
    except:
        opts.err('Invalid domain: ' + dom)
        
    mode = shutdown_mode(opts)  
    shutdown(opts, [ domid ], mode, opts.vals.wait)
    
def main(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
        return
    print 'shutdown.main>', len(args), args
    if opts.vals.all:
        main_all(opts, args)
    else:
        main_dom(opts, args)
        
