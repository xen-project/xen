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

"""Destroy a domain.
"""

from xen.xend.XendClient import server
from xen.xm.opts import *

gopts = Opts(use="""[DOM]

Destroy a domain.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

def main(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
        return
    if len(args) < 1: opts.err('Missing domain')
    dom = args[0]
    server.xend_domain_destroy(dom)
