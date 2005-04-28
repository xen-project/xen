# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xen.xend import sxp
from xen.xend import XendConsole
from xen.web.SrvDir import SrvDir

class SrvConsole(SrvDir):
    """An individual console.
    """

    def __init__(self, info):
        SrvDir.__init__(self)
        self.info = info
        self.xc = XendConsole.instance()

    def op_disconnect(self, op, req):
        val = self.xc.console_disconnect(self.info.console_port)
        return val

    def render_POST(self, req):
        return self.perform(req)
        
    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-Type", sxp.mime_type)
            sxp.show(self.info.sxpr(), out=req)
        else:
            req.write('<html><head></head><body>')
            self.print_path(req)
            #self.ls()
            req.write('<p>%s</p>' % self.info)
            req.write('<p><a href="%s">Connect to domain %d</a></p>'
                      % (self.info.uri(), self.info.dom))
            self.form(req)
            req.write('</body></html>')

    def form(self, req):
        req.write('<form method="post" action="%s">' % req.prePathURL())
        if self.info.connected():
            req.write('<input type="submit" name="op" value="disconnect">')
        req.write('</form>')
