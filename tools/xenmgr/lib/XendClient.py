# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Client API for the HTTP interface on xend.
Callable as a script - see main().
"""
import sys
import httplib
import types
from StringIO import StringIO
import urlparse

from encode import *
import sxp
import PrettyPrint

DEBUG = 0

class Foo(httplib.HTTPResponse):

    def begin(self):
        fin = self.fp
        while(1):
            buf = fin.readline()
            print "***", buf
            if buf == '':
                print
                sys.exit()


def sxprio(sxpr):
    io = StringIO()
    sxp.show(sxpr, out=io)
    print >> io
    io.seek(0)
    return io

def fileof(val):
    """Converter for passing configs.
    Handles lists, files directly.
    Assumes a string is a file name and passes its contents.
    """
    if isinstance(val, types.ListType):
        return sxprio(val)
    if isinstance(val, types.StringType):
        return file(val)
    if hasattr(val, 'readlines'):
        return val

# todo: need to sort of what urls/paths are using for objects.
# e.g. for domains at the moment return '0'.
# should probably return abs path w.r.t. server, e.g. /xend/domain/0.
# As an arg, assume abs path is obj uri, otherwise just id.

# Function to convert to full url: Xend.uri(path), e.g.
# maps /xend/domain/0 to http://wray-m-3.hpl.hp.com:8000/xend/domain/0
# And should accept urls for ids?

def urljoin(location, root, prefix='', rest=''):
    prefix = str(prefix)
    rest = str(rest)
    base = 'http://' + location + root + prefix
    url = urlparse.urljoin(base, rest)
    return url

def nodeurl(location, root, id=''):
    return urljoin(location, root, 'node/', id)

def domainurl(location, root, id=''):
    return urljoin(location, root, 'domain/', id)

def consoleurl(location, root, id=''):
    return urljoin(location, root, 'console/', id)

def deviceurl(location, root, id=''):
    return urljoin(location, root, 'device/', id)

def vneturl(location, root, id=''):
    return urljoin(location, root, 'vnet/', id)

def eventurl(location, root, id=''):
    return urljoin(location, root, 'event/', id)

def xend_request(url, method, data=None):
    urlinfo = urlparse.urlparse(url)
    (uproto, ulocation, upath, uparam, uquery, ufrag) = urlinfo
    if DEBUG: print url, urlinfo
    if uproto != 'http':
        raise StandardError('Invalid protocol: ' + uproto)
    if DEBUG: print '>xend_request', ulocation, upath, method, data
    (hdr, args) = encode_data(data)
    if data and method == 'GET':
        upath += '?' + args
        args = None
    if method == "POST" and upath.endswith('/'):
        upath = upath[:-1]
    if DEBUG: print "ulocation=", ulocation, "upath=", upath, "args=", args
    #hdr['User-Agent'] = 'Mozilla'
    #hdr['Accept'] = 'text/html,text/plain'
    conn = httplib.HTTPConnection(ulocation)
    #conn.response_class = Foo
    if DEBUG: conn.set_debuglevel(1)
    conn.request(method, upath, args, hdr)
    resp = conn.getresponse()
    if DEBUG: print resp.status, resp.reason
    if DEBUG: print resp.msg.headers
    if resp.status in [204, 404]:
        return None
    if resp.status not in [200, 201, 202, 203]:
        raise RuntimeError(resp.reason)
    pin = sxp.Parser()
    data = resp.read()
    if DEBUG: print "***data" , data
    if DEBUG: print "***"
    pin.input(data);
    pin.input_eof()
    conn.close()
    val = pin.get_val()
    #if isinstance(val, types.ListType) and sxp.name(val) == 'val':
    #    val = val[1]
    if isinstance(val, types.ListType) and sxp.name(val) == 'err':
        raise RuntimeError(val[1])
    if DEBUG: print '**val='; sxp.show(val); print
    return val

def xend_get(url, args=None):
    return xend_request(url, "GET", args)

def xend_call(url, data):
    return xend_request(url, "POST", data)

class Xend:

    SRV_DEFAULT = "localhost:8000"
    ROOT_DEFAULT = "/xend/"

    def __init__(self, srv=None, root=None):
        self.bind(srv, root)

    def bind(self, srv=None, root=None):
        if srv is None: srv = self.SRV_DEFAULT
        if root is None: root = self.ROOT_DEFAULT
        if not root.endswith('/'): root += '/'
        self.location = srv
        self.root = root

    def nodeurl(self, id=''):
        return nodeurl(self.location, self.root, id)

    def domainurl(self, id=''):
        return domainurl(self.location, self.root, id)

    def consoleurl(self, id=''):
        return consoleurl(self.location, self.root, id)

    def deviceurl(self, id=''):
        return deviceurl(self.location, self.root, id)

    def vneturl(self, id=''):
        return vneturl(self.location, self.root, id)

    def eventurl(self, id=''):
        return eventurl(self.location, self.root, id)

    def xend(self):
        return xend_get(urljoin(self.location, self.root))

    def xend_node(self):
        return xend_get(self.nodeurl())

    def xend_node_cpu_rrobin_slice_set(self, slice):
        return xend_call(self.nodeurl(),
                         {'op'      : 'cpu_rrobin_slice_set',
                          'slice'   : slice })
    
    def xend_node_cpu_bvt_slice_set(self, slice):
        return xend_call(self.nodeurl(),
                         {'op'      : 'cpu_bvt_slice_set',
                          'slice'   : slice })

    def xend_domains(self):
        return xend_get(self.domainurl())

    def xend_domain_create(self, conf):
        return xend_call(self.domainurl(),
                         {'op'      : 'create',
                          'config'  : fileof(conf) })

    def xend_domain(self, id):
        return xend_get(self.domainurl(id))

    def xend_domain_unpause(self, id):
        return xend_call(self.domainurl(id),
                         {'op'      : 'unpause'})

    def xend_domain_pause(self, id):
        return xend_call(self.domainurl(id),
                         {'op'      : 'pause'})

    def xend_domain_shutdown(self, id):
        return xend_call(self.domainurl(id),
                         {'op'      : 'shutdown'})

    def xend_domain_halt(self, id):
        return xend_call(self.domainurl(id),
                         {'op'      : 'halt'})

    def xend_domain_save(self, id, filename):
        return xend_call(self.domainurl(id),
                         {'op'      : 'save',
                          'file'    : filename})

    def xend_domain_restore(self, id, filename, conf):
        return xend_call(self.domainurl(id),
                         {'op'      : 'restore',
                          'file'    : filename,
                          'config'  : fileof(conf) })

    def xend_domain_migrate(self, id, dst):
        return xend_call(self.domainurl(id),
                         {'op'      : 'migrate',
                          'dst'     : dst})

    def xend_domain_pincpu(self, id, cpu):
        return xend_call(self.domainurl(id),
                         {'op'      : 'pincpu',
                          'cpu'     : cpu})

    def xend_domain_cpu_bvt_set(self, id, mcuadv, warp, warpl, warpu):
        return xend_call(self.domainurl(id),
                         {'op'      : 'cpu_bvt_set',
                          'mcuadv'  : mvuadv,
                          'warp'    : warp,
                          'warpl'   : warpl,
                          'warpu'   : warpu })

    def xend_domain_cpu_atropos_set(self, id, period, slice, latency, xtratime):
        return xend_call(self.domainurl(id),
                         {'op'      : 'cpu_atropos_set',
                          'period'  : period,
                          'slice'   : slice,
                          'latency' : latency,
                          'xtratime': xtratime })

    def xend_domain_vifs(self, id):
        return xend_get(self.domainurl(id),
                        { 'op'      : 'vifs' })
    
    def xend_domain_vif_ip_add(self, id, vif, ipaddr):
        return xend_call(self.domainurl(id),
                         {'op'      : 'vif_ip_add',
                          'vif'     : vif,
                          'ip'      : ipaddr })
        
    def xend_domain_vbds(self, id):
        return xend_get(self.domainurl(id),
                        {'op'       : 'vbds'})

    def xend_domain_vbd(self, id, vbd):
        return xend_get(self.domainurl(id),
                        {'op'       : 'vbd',
                         'vbd'      : vbd})

    def xend_consoles(self):
        return xend_get(self.consoleurl())

    def xend_console(self, id):
        return xend_get(self.consoleurl(id))

    def xend_vnets(self):
        return xend_get(self.vneturl())

    def xend_vnet_create(self, conf):
        return xend_call(self.vneturl(),
                         {'op': 'create', 'config': fileof(conf) })

    def xend_vnet(self, id):
        return xend_get(self.vneturl(id))

    def xend_vnet_delete(self, id):
        return xend_call(self.vneturl(id),
                         {'op': 'delete'})

    def xend_event_inject(self, sxpr):
        val = xend_call(self.eventurl(),
                        {'op': 'inject', 'event': fileof(sxpr) })
    

def main(argv):
    """Call an API function:
    
    python XendClient.py fn args...

    The leading 'xend_' on the function can be omitted.
    Example:

    > python XendClient.py domains
    (domain 0 8)
    > python XendClient.py domain 0
    (domain (id 0) (name Domain-0) (memory 128))
    """
    server = Xend()
    fn = argv[1]
    if not fn.startswith('xend'):
        fn = 'xend_' + fn
    args = argv[2:]
    val = getattr(server, fn)(*args)
    PrettyPrint.prettyprint(val)
    print

if __name__ == "__main__":
    main(sys.argv)
else:    
    server = Xend()
