#!/usr/bin/env python
# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Client API for the HTTP interface on xend.
Callable as a script - see main().
Supports synchronous or asynchronous connection to xend.

This API is the 'control-plane' for xend.
The 'data-plane' is done separately. For example, consoles
are accessed via sockets on xend, but the list of consoles
is accessible via this API.
"""
import os
import sys
import types

import sxp
import PrettyPrint
from XendProtocol import XendClientProtocol, SynchXendClientProtocol, XendError

DEBUG = 0

def fileof(val):
    """Converter for passing configs or other 'large' data.
    Handles lists, files directly.
    Assumes a string is a file name and passes its contents.
    """
    if isinstance(val, types.ListType):
        return sxp.to_string(val)
    if isinstance(val, types.StringType):
        return file(val)
    if hasattr(val, 'readlines'):
        return val
    raise XendError('cannot convert value')

# todo: need to sort of what urls/paths are using for objects.
# e.g. for domains at the moment return '0'.
# should probably return abs path w.r.t. server, e.g. /xend/domain/0.
# As an arg, assume abs path is obj uri, otherwise just id.

# Function to convert to full url: Xend.uri(path), e.g.
# maps /xend/domain/0 to http://wray-m-3.hpl.hp.com:8000/xend/domain/0
# And should accept urls for ids?

class URL:
    """A URL.
    """

    def __init__(self, proto='http', host='localhost', port=None, path='', query=None, frag=None):
        self.proto = proto
        self.host = host
        if port: port = int(port)
        self.port = port
        self.path = path
        self.query = query
        self.frag = frag

    def url(self):
        """Get the full URL string including protocol, location and the full path.
        """
        return self.proto + '://' + self.location() + self.fullpath()

    def location(self):
        """Get the location part of the URL, including host and port, if present.
        """
        if self.port:
            return self.host + ':' + str(self.port)
        else:
            return self.host

    def fullpath(self):
        """Get the full path part of the URL, including query and fragment if present.
        """
        u = [ self.path ]
        if self.query:
            u.append('?')
            u.append(self.query)
        if self.frag:
            u.append('#')
            u.append(self.frag)
        return ''.join(u)

    def relative(self, path='', query=None, frag=None):
        """Create a URL relative to this one.
        """
        return URL(proto=self.proto,
                   host=self.host,
                   port=self.port,
                   path=self.path + path,
                   query=query,
                   frag=frag)

class Xend:
    """Client interface to Xend.
    """

    """Default location of the xend server."""
    SRV_DEFAULT = "localhost:8000"

    """Environment variable to set the location of xend."""
    SRV_VAR = "XEND"

    """Default path to the xend root on the server."""
    ROOT_DEFAULT = "/xend/"

    """Environment variable to set the xend root path."""
    ROOT_VAR = "XEND_ROOT"

    def __init__(self, client=None, srv=None, root=None):
        """Create a xend client interface.
        If the client protocol is not specified, the default
        is to use a synchronous protocol.

        @param client:  client protocol to use
        @param srv:     server host, and optional port (format host:port)
        @param root:    xend root path on the server
        """
        if client is None:
            client = SynchXendClientProtocol()
        self.client = client
        self.bind(srv, root)

    def default_server(self):
        """Get the default location of the xend server.
        """
        return os.getenv(self.SRV_VAR, self.SRV_DEFAULT)

    def default_root(self):
        """Get the default root path on the xend server.
        """
        return os.getenv(self.ROOT_VAR, self.ROOT_DEFAULT)

    def bind(self, srv=None, root=None):
        """Bind to a given server.

        @param srv:  server location (host:port)
        @param root: xend root path on the server
        """
        if srv is None: srv = self.default_server()
        if root is None: root = self.default_root()
        if not root.endswith('/'): root += '/'
        (host, port) = srv.split(':', 1)
        self.url = URL(host=host, port=port, path=root)

    def xendGet(self, url, args=None):
        return self.client.xendGet(url, args)

    def xendPost(self, url, data):
        return self.client.xendPost(url, data)

    def nodeurl(self, id=''):
        return self.url.relative('node/' + str(id))

    def domainurl(self, id=''):
        return self.url.relative('domain/' + str(id))

    def consoleurl(self, id=''):
        return self.url.relative('console/' + str(id))

    def deviceurl(self, id=''):
        return self.url.relative('device/' + str(id))

    def vneturl(self, id=''):
        return self.url.relative('vnet/' + str(id))

    def eventurl(self, id=''):
        return self.url.relative('event/' + str(id))

    def xend(self):
        return self.xendGet(self.url)

    def xend_node(self):
        return self.xendGet(self.nodeurl())
        
    def xend_node_shutdown(self):
        return self.xendPost(self.nodeurl(),
                             {'op'      : 'shutdown'})
                
    def xend_node_restart(self):
        return self.xendPost(self.nodeurl(),
                             {'op'      : 'reboot'})

    def xend_node_dmesg(self):
        return self.xendGet(self.nodeurl('dmesg'))

    def xend_node_log(self):
        return self.xendGet(self.nodeurl('log'))

    def xend_node_cpu_rrobin_slice_set(self, slice):
        return self.xendPost(self.nodeurl(),
                             {'op'      : 'cpu_rrobin_slice_set',
                              'slice'   : slice })

    def xend_node_cpu_bvt_slice_set(self, ctx_allow):
        return self.xendPost(self.nodeurl(),
                             {'op'      : 'cpu_bvt_slice_set',
                              'ctx_allow' : ctx_allow })

    def xend_node_cpu_fbvt_slice_set(self, ctx_allow):
        return self.xendPost(self.nodeurl(),
                             {'op'      : 'cpu_fbvt_slice_set',
                              'ctx_allow' : ctx_allow })

    def xend_domains(self):
        return self.xendGet(self.domainurl())

    def xend_domain_create(self, conf):
        return self.xendPost(self.domainurl(),
                             {'op'      : 'create',
                              'config'  : fileof(conf) })

    def xend_domain_restore(self, filename):
        return self.xendPost(self.domainurl(),
                             {'op'      : 'restore',
                              'file'    : filename })

    def xend_domain_configure(self, id, conf):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'configure',
                              'config'  : fileof(conf) })

    def xend_domain(self, id):
        return self.xendGet(self.domainurl(id))

    def xend_domain_unpause(self, id):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'unpause' })

    def xend_domain_pause(self, id):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'pause' })

    def xend_domain_shutdown(self, id, reason):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'shutdown',
                              'reason'  : reason })

    def xend_domain_destroy(self, id, reason):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'destroy',
                              'reason'  : reason })

    def xend_domain_save(self, id, filename):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'save',
                              'file'    : filename })

    def xend_domain_migrate(self, id, dst, live=0):
        return self.xendPost(self.domainurl(id),
                             {'op'         : 'migrate',
                              'destination': dst,
                              'live'       : live })

    def xend_domain_pincpu(self, id, cpu):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'pincpu',
                              'cpu'     : cpu })

    def xend_domain_cpu_bvt_set(self, id, mcuadv, warpback, warpvalue, warpl, warpu):
        return self.xendPost(self.domainurl(id),
                             {'op'       : 'cpu_bvt_set',
                              'mcuadv'   : mcuadv,
                              'warpback' : warpback,
                              'warpvalue': warpvalue,
                              'warpl'    : warpl,
                              'warpu'    : warpu })

    def xend_domain_cpu_fbvt_set(self, id, mcuadv, warp, warpl, warpu):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'cpu_fbvt_set',
                              'mcuadv'  : mcuadv,
                              'warp'    : warp,
                              'warpl'   : warpl,
                              'warpu'   : warpu })

    def xend_domain_cpu_atropos_set(self, id, period, slice, latency, xtratime):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'cpu_atropos_set',
                              'period'  : period,
                              'slice'   : slice,
                              'latency' : latency,
                              'xtratime': xtratime })

    def xend_domain_maxmem_set(self, id, memory):
        return self.xendPost(self.domainurl(id),
                             { 'op'     : 'maxmem_set',
                               'memory' : memory })

    def xend_domain_vifs(self, id):
        return self.xendGet(self.domainurl(id),
                            { 'op'      : 'vifs' })

    def xend_domain_vif(self, id, vif):
        return self.xendGet(self.domainurl(id),
                            { 'op'      : 'vif',
                              'vif'     : vif })

    def xend_domain_vbds(self, id):
        return self.xendGet(self.domainurl(id),
                            {'op'       : 'vbds'})

    def xend_domain_vbd(self, id, vbd):
        return self.xendGet(self.domainurl(id),
                            {'op'       : 'vbd',
                             'vbd'      : vbd })

    def xend_domain_device_create(self, id, config):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'device_create',
                              'config'  : fileof(config) })

    def xend_domain_device_destroy(self, id, type, idx):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'device_destroy',
                              'type'    : type,
                              'idx'     : idx })

    def xend_domain_device_configure(self, id, config, idx):
        return self.xendPost(self.domainurl(id),
                             {'op'      : 'device_configure',
                              'idx'     : idx,
                              'config'  : fileof(config) })

    def xend_consoles(self):
        return self.xendGet(self.consoleurl())

    def xend_console(self, id):
        return self.xendGet(self.consoleurl(id))

    def xend_console_disconnect(self, id):
        return self.xendPost(self.consoleurl(id),
                             {'op'      : 'disconnect'})

    def xend_vnets(self):
        return self.xendGet(self.vneturl())

    def xend_vnet_create(self, conf):
        return self.xendPost(self.vneturl(),
                             {'op'      : 'create',
                              'config'  : fileof(conf) })

    def xend_vnet(self, id):
        return self.xendGet(self.vneturl(id))

    def xend_vnet_delete(self, id):
        return self.xendPost(self.vneturl(id),
                              {'op'     : 'delete' })

    def xend_event_inject(self, sxpr):
        val = self.xendPost(self.eventurl(),
                             {'op'      : 'inject',
                              'event'   : fileof(sxpr) })

    def xend_domain_mem_target_set(self, id, mem_target):
        val = self.xendPost(self.domainurl(id),
                            {'op'         : 'mem_target_set',
                             'target'     : mem_target })
        return val

def getAsynchXendClientProtocol():
    """Load AsynchXendClientProtocol on demand to avoid the cost.
    """
    global AsynchXendClientProtocol
    try:
       AsynchXendClientProtocol
    except:
        from XendAsynchProtocol import AsynchXendClientProtocol
    return AsynchXendClientProtocol

def getAsynchServer():
    """Load AsynchXendClientProtocol and create an asynch xend client.

    @return asynch Xend
    """
    getAsynchXendClientProtocol()
    return Xend(AsynchXendClientProtocol())

def xendmain(srv, asynch, fn, args):
    if asynch:
        getAsynchXendClientProtocol()
        client = AsynchXendClientProtocol() 
    else:
        client = None
    xend = Xend(srv=srv, client=client)
    xend.rc = 0
    try:
        v = getattr(xend, fn)(*args)
    except XendError, err:
        print 'ERROR:', err
        return 1
    if asynch:
        def cbok(val):
            PrettyPrint.prettyprint(val)
            reactor.stop()
        def cberr(err):
            print 'ERROR:', err
            xend.rc = 1
            reactor.stop()
        v.addCallback(cbok)
        v.addErrback(cberr)
        reactor.run()
        return xend.rc
    else:
        PrettyPrint.prettyprint(v)
        return 0

def main(argv):
    """Call an API function:

    python XendClient.py fn args...

    The leading 'xend_' on the function can be omitted.
    Example:

python XendClient.py domains
    (0 8)
python XendClient.py domain 0
    (domain (id 0) (name Domain-0) (memory 128))
    """
    global DEBUG
    from getopt import getopt
    short_options = 'x:ad'
    long_options = ['xend=', 'asynch', 'debug']
    (options, args) = getopt(argv[1:], short_options, long_options)
    srv = None
    asynch = 0
    for k, v in options:
        if k in ['-x', '--xend']:
            srv = v
        elif k in ['-a', '--asynch']:
            asynch = 1
        elif k in ['-d', '--debug']:
            DEBUG = 1
    if len(args):
        fn = args[0]
        args = args[1:]
    else:
        fn = 'xend'
        args = []
    if not fn.startswith('xend'):
        fn = 'xend_' + fn
    sys.exit(xendmain(srv, asynch, fn, args))

if __name__ == "__main__":
    main(sys.argv)
else:    
    server = Xend()
