#!/usr/bin/python2
# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Example xend HTTP and console server.

   Can be accessed from a browser or from a program.
   Do 'python SrvServer.py' to run the server.
   Then point a web browser at http://localhost:8000/xend and follow the links.
   Most are stubs, except /domain which has a list of domains and a 'create domain'
   button.

   You can also access the server from a program.
   Do 'python XendClient.py' to run a few test operations.

   The data served differs depending on the client (as defined by User-Agent
   and Accept in the HTTP headers). If the client is a browser, data
   is returned in HTML, with interactive forms. If the client is a program,
   data is returned in SXP format, with no forms.

   The server serves to the world by default. To restrict it to the local host
   change 'interface' in main().

   Mike Wray <mike.wray@hp.com>
"""
# todo Support security settings etc. in the config file.
# todo Support command-line args.

from twisted.web import server
from twisted.web import resource
from twisted.internet import reactor

from xenmgr import XendRoot
xroot = XendRoot.instance()

from xenmgr import XendBridge

from SrvRoot import SrvRoot

def create(port=None, interface=None, bridge=0):
    if port is None: port = 8000
    if interface is None: interface = ''
    if bridge or xroot.rebooted:
        init_bridge()
    root = resource.Resource()
    xend = SrvRoot()
    root.putChild('xend', xend)
    site = server.Site(root)
    reactor.listenTCP(port, site, interface=interface)

def init_bridge():
    XendBridge.bridge_create()
    XendBridge.reconfigure()

def main(port=None, interface=None):
    create(port, interface)
    reactor.run()


if __name__ == '__main__':
    main()
