# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from twisted.protocols import http
from twisted.web import error

from xen.xend import sxp
from xen.xend.XendError import XendError

from SrvBase import SrvBase

class SrvError(error.ErrorPage):

    def render(self, request):
        val = error.ErrorPage.render(self, request)
        request.setResponseCode(self.code, self.brief)
        return val

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

    def noChild(self, msg):
        return SrvError(http.NOT_FOUND, msg, msg)

    def getChild(self, x, req):
        if x == '': return self
        try:
            val = self.get(x)
        except XendError, ex:
            return self.noChild(str(ex))
        if val is None:
            return self.noChild('Not found ' + str(x))
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
        try:
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
        except Exception, ex:
            self._perform_err(ex, "GET", req)
            
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
