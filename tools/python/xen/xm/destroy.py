# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Destroy a domain.
"""

from xen.xend.XendClient import server
from xen.xm.opts import *

gopts = Opts(use="""[options] [DOM]

Destroy a domain, optionally restarting it.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

gopts.opt('reboot', short='R',
          fn=set_true, default=0,
          use='Destroy and restart.')

def main(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
        return
    if len(args) < 1: opts.err('Missing domain')
    dom = args[0]
    try:
        domid = int(dom)
    except:
        opts.err('Invalid domain: ' + dom)
    if opts.vals.reboot:
        mode = 'reboot'
    else:
        mode = 'halt'
    server.xend_domain_destroy(domid, mode)
    
        
