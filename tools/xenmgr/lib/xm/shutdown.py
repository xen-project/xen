import string
import sys
import time

from xenmgr.XendClient import server
from xenmgr.xm import opts

opts = Opts(use="""[options] [DOM]

Shutdown one or more domains gracefully.""")

opts.opt('help', short='h',
         fn=set_value, default=0,
         use="Print this help.")

opts.opt('all', short='a',
         fn=set_true, default=0,
         use="Shutdown all domains.")

opts.opt('wait', short='w',
         fn=set_true, default=0,
         use='Wait for shutdown to complete.')

def shutdown(opts, doms, wait):
    def domains():
        return [ int(a) for a in server.xend_domains() ]
    if doms == None: doms = domains()
    if 0 in doms:
        doms.remove(0)
    for d in doms:
        server.xend_domain_shutdown(dom)
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
    shutdown(opts, None, opts.wait)

def main_dom(opts, args):
    if len(args) < 2: opts.err('Missing domain')
    dom = argv[1]
    try:
        domid = int(dom)
    except:
        opts.err('Invalid domain: ' + dom)
    shutdown(opts, [ domid ], opts.wait)
    
def main(argv):
    args = opts.parse(argv)
    if opts.help:
        opts.usage()
    if opts.all:
        main_all(opts, args)
    else:
        main_dom(opts, args)
        
