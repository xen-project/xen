# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Domain migration.
"""

import sys

from xen.xend.XendClient import server
from xen.xm.opts import *

DOM0_NAME = 'Domain-0'
DOM0_ID = '0'

gopts = Opts(use="""[options] DOM HOST

Migrate domain DOM to host HOST.
The transfer daemon xfrd must be running on the
local host and on HOST.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

def help(argv):
    gopts.usage()
    
def main(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
        return
    if len(args) != 2:
        opts.err('Invalid arguments')
    dom = args[0]
    dst = args[1]
    if dom in [DOM0_NAME, DOM0_ID]:
        opts.err('Cannot migrate ' + dom)
    server.xend_domain_migrate(dom, dst)
        
