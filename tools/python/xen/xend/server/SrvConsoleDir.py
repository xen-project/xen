# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xen.web.SrvDir import SrvDir
from SrvConsole import SrvConsole
from xen.xend import XendConsole
from xen.xend import sxp

class SrvConsoleDir(SrvDir):
    """Console directory.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.xconsole = XendConsole.instance()

    def console(self, x):
        val = None
        try:
            info = self.xconsole.console_get(x)
            val = SrvConsole(info)
        except KeyError, ex:
            print 'SrvConsoleDir>', ex
            pass
        return val

    def get(self, x):
        v = SrvDir.get(self, x)
        if v is not None:
            return v
        v = self.console(x)
        return v

    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-Type", sxp.mime_type)
            self.ls_console(req, 1)
        else:
            req.write("<html><head></head><body>")
            self.print_path(req)
            self.ls(req)
            self.ls_console(req)
            #self.form(req.wfile)
            req.write("</body></html>")

    def ls_console(self, req, use_sxp=0):
        url = req.prePathURL()
        if not url.endswith('/'):
            url += '/'
        if use_sxp:
            consoles = self.xconsole.console_ls()
            sxp.show(consoles, out=req)
        else:
            consoles = self.xconsole.consoles()
            consoles.sort(lambda x, y: cmp(x.console_port, y.console_port))
            req.write('<ul>')
            for c in consoles:
                cid = str(c.console_port)
                req.write('<li><a href="%s%s"> %s</a></li>' % (url, cid, cid))
            req.write('</ul>')
