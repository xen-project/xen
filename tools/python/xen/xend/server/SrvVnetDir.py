# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xen.xend import sxp
from xen.xend.Args import FormFn
from xen.xend import PrettyPrint
from xen.xend import XendVnet

from SrvDir import SrvDir

class SrvVnet(SrvDir):

    def __init__(self, vnetinfo):
        SrvDir.__init__(self)
        self.vnetinfo = vnetinfo
        self.xvnet = XendVnet.instance()

    def op_delete(self, op, req):
        val = self.xvnet.vnet_delete(self.vnetinfo.id)
        return val

    def render_POST(self, req):
        return self.perform(req)
        
    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-Type", sxp.mime_type)
            sxp.show(self.vnetinfo.sxpr(), out=req)
        else:
            req.write('<html><head></head><body>')
            self.print_path(req)
            req.write('<p>Vnet %s</p>' % self.vnetinfo.id)
            req.write("<code><pre>")
            PrettyPrint.prettyprint(self.vnetinfo.sxpr(), out=req)
            req.write("</pre></code>")
            self.form(req)
            req.write('</body></html>')
        return ''

    def form(self, req):
        url = req.prePathURL()
        req.write('<form method="post" action="%s">' % url)
        req.write('<input type="submit" name="op" value="delete">')
        req.write('</form>')
        
class SrvVnetDir(SrvDir):
    """Vnet directory.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.xvnet = XendVnet.instance()

    def vnet(self, x):
        val = None
        vnetinfo = self.xvnet.vnet_get(x)
        if not vnetinfo:
            raise XendError('No such vnet ' + str(x))
        val = SrvVnet(vnetinfo)
        return val

    def get(self, x):
        v = SrvDir.get(self, x)
        if v is not None:
            return v
        v = self.vnet(x)
        return v

    def op_create(self, op, req):
        fn = FormFn(self.xvnet.vnet_create,
                    [['config', 'sxpr']])
        val = fn(req.args, {})
        return val
        
    def render_POST(self, req):
        return self.perform(req)

    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-Type", sxp.mime_type)
            self.ls_vnet(req, 1)
        else:
            req.write("<html><head></head><body>")
            self.print_path(req)
            self.ls(req)
            self.ls_vnet(req)
            self.form(req)
            req.write("</body></html>")

    def ls_vnet(self, req, use_sxp=0):
        url = req.prePathURL()
        if not url.endswith('/'):
            url += '/'
        if use_sxp:
            vnets = self.xvnet.vnet_ls()
            sxp.show(vnets, out=req)
        else:
            vnets = self.xvnet.vnets()
            vnets.sort(lambda x, y: cmp(x.id, y.id))
            req.write('<ul>')
            for v in vnets:
               req.write('<li><a href="%s%s"> Vnet %s</a>' % (url, v.id, v.id))
               req.write('</li>')
            req.write('</ul>')

    def form(self, req):
        """Generate the form(s) for vnet dir operations.
        """
        req.write('<form method="post" action="%s" enctype="multipart/form-data">'
                  % req.prePathURL())
        req.write('<button type="submit" name="op" value="create">Create Vnet</button>')
        req.write('Config <input type="file" name="config"><br>')
        req.write('</form>')
