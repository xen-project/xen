# (C) Matthew Bloch <matthew@bytemark.co.uk> 2004
# Copyright (C) 2005 XenSource Ltd

"""Domain sysrq.
"""

from xen.xend.XendClient import server
from xen.xm.opts import *

gopts = Opts(use="""[DOM] [letter]

Sends a Linux sysrq to a domain.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

def main(argv):
    opts = gopts
    args = opts.parse(argv)

    if len(args) < 1:
        raise OptionError('Missing domain argument')
    if len(args) < 2:
        raise OptionError('Missing sysrq character')

    dom = args[0]
    req = ord(args[1][0])
    server.xend.domain.send_sysrq(dom, req)
