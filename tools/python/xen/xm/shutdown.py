# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Domain shutdown.
"""
import string
import sys
import time

from xen.xend.XendClient import server
from xen.xm.opts import *

gopts = Opts(use="""[options] [DOM]

Shutdown one or more domains gracefully.""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

gopts.opt('all', short='a',
         fn=set_true, default=0,
         use="Shutdown all domains.")

gopts.opt('wait', short='w',
         fn=set_true, default=0,
         use='Wait for shutdown to complete.')

gopts.opt('norestart', short='n',
          fn=set_true, default=0,
          use='Prevent domain restart.')

def shutdown(opts, doms, wait):
    def domains():
        return [ int(a) for a in server.xend_domains() ]
    if doms == None: doms = domains()
    if 0 in doms:
        doms.remove(0)
    for d in doms:
        server.xend_domain_shutdown(d)
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

def main_all(opts, args):
    shutdown(opts, None, opts.vals.wait)

def main_dom(opts, args):
    if len(args) < 1: opts.err('Missing domain')
    dom = args[0]
    try:
        domid = int(dom)
    except:
        opts.err('Invalid domain: ' + dom)
    shutdown(opts, [ domid ], opts.vals.wait)
    
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
        
