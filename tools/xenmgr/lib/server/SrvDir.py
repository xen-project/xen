# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from twisted.web import error
from xenmgr import sxp
from SrvBase import SrvBase

class SrvConstructor:
    """Delayed constructor for sub-servers.
    Does not import the sub-server class or create the object until needed.
    """
    
    def __init__(self, klass):
        """Create a constructor. It is assumed that the class
        should be imported as 'import klass from klass'.

        klass	name of its class
        """
        self.klass = klass
        self.obj = None

    def getobj(self):
        """Get the sub-server object, importing its class and instantiating it if
        necessary.
        """
        if not self.obj:
            exec 'from %s import %s' % (self.klass, self.klass)
            klassobj = eval(self.klass)
            self.obj = klassobj()
        return self.obj

class SrvDir(SrvBase):
    """Base class for directory servlets.
    """
    isLeaf = False
    
    def __init__(self):
        SrvBase.__init__(self)
        self.table = {}
        self.order = []

    def getChild(self, x, req):
        if x == '': return self
        val = self.get(x)
        if val is None:
            return error.NoResource('Not found')
        else:
            return val

    def get(self, x):
        val = self.table.get(x)
        if val is not None:
            val = val.getobj()
        return val

    def add(self, x, xclass = None):
        if xclass is None:
            xclass = 'SrvDir'
        self.table[x] = SrvConstructor(xclass)
        self.order.append(x)

    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-type", sxp.mime_type)
            self.ls(req, 1)
        else:
            req.write('<html><head></head><body>')
            self.print_path(req)
            self.ls(req)
            self.form(req)
            req.write('</body></html>')
        return ''
            
    def ls(self, req, use_sxp=0):
        url = req.prePathURL()
        if not url.endswith('/'):
            url += '/'
        if use_sxp:
           req.write('(ls ')
           for k in self.order:
               req.write(' ' + k)
           req.write(')')
        else:
            req.write('<ul>')
            for k in self.order:
                v = self.get(k)
                req.write('<li><a href="%s%s">%s</a></li>'
                          % (url, k, k))
            req.write('</ul>')

    def form(self, req):
        pass
