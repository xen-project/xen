# (C) Matthew Bloch <matthew@bytemark.co.uk> 2004

"""Domain shutdown.
"""
import string
import sys
import time

from xen.xend.XendClient import server
from xen.xm.opts import *

DOM0_NAME = 'Domain-0'
DOM0_ID = '0'

gopts = Opts(use="""[DOM] [letter]

Sends a Linux sysrq to a domain.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

def sysrq(dom, req):
    server.xend_domain_shutdown(dom, 'sysrq', req)

def main(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
        return
        
    # no options for the moment
    if len(args) < 1: opts.err('Missing domain')
    if len(args) < 2: opts.err('Missing sysrq character')
    dom = args[0]
    req = ord(args[1][0])
    sysrq(dom, req)
