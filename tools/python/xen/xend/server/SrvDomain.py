# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from twisted.protocols import http

from xen.xend import sxp
from xen.xend import XendDomain
from xen.xend import XendConsole
from xen.xend import PrettyPrint
from xen.xend.Args import FormFn

from SrvDir import SrvDir

class SrvDomain(SrvDir):
    """Service managing a single domain.
    """

    def __init__(self, dom):
        SrvDir.__init__(self)
        self.dom = dom
        self.xd = XendDomain.instance()
        self.xconsole = XendConsole.instance()

    def op_configure(self, op, req):
        """Configure an existing domain.
        Configure is unusual in that it requires a domain id,
        not a domain name.
        """
        fn = FormFn(self.xd.domain_configure,
                    [['dom', 'int'],
                     ['config', 'sxpr']])
        deferred = fn(req.args, {'dom': self.dom.dom})
        deferred.addErrback(self._op_configure_err, req)
        return deferred

    def _op_configure_err(self, err, req):
        req.setResponseCode(http.BAD_REQUEST, "Error: "+ str(err))
        return str(err)
        
    def op_unpause(self, op, req):
        val = self.xd.domain_unpause(self.dom.name)
        return val
        
    def op_pause(self, op, req):
        val = self.xd.domain_pause(self.dom.name)
        return val

    def op_shutdown(self, op, req):
        fn = FormFn(self.xd.domain_shutdown,
                    [['dom', 'str'],
                     ['reason', 'str'],
                     ['key', 'int']])
        val = fn(req.args, {'dom': self.dom.id})
        req.setResponseCode(http.ACCEPTED)
        req.setHeader("Location", "%s/.." % req.prePathURL())
        return val

    def op_destroy(self, op, req):
        fn = FormFn(self.xd.domain_destroy,
                    [['dom', 'str'],
                     ['reason', 'str']])
        val = fn(req.args, {'dom': self.dom.id})
        req.setHeader("Location", "%s/.." % req.prePathURL())
        return val

    def op_save(self, op, req):
        fn = FormFn(self.xd.domain_save,
                    [['dom', 'str'],
                     ['file', 'str']])
        deferred = fn(req.args, {'dom': self.dom.id})
        deferred.addCallback(self._op_save_cb, req)
        deferred.addErrback(self._op_save_err, req)
        return deferred

    def _op_save_cb(self, val, req):
        return 0

    def _op_save_err(self, err, req):
        req.setResponseCode(http.BAD_REQUEST, "Error: "+ str(err))
        return str(err)
        
    def op_migrate(self, op, req):
        fn = FormFn(self.xd.domain_migrate,
                    [['dom', 'str'],
                     ['destination', 'str'],
                     ['live', 'int'],
                     ['resource', 'int']])
        deferred = fn(req.args, {'dom': self.dom.id})
        print 'op_migrate>', deferred
        deferred.addCallback(self._op_migrate_cb, req)
        deferred.addErrback(self._op_migrate_err, req)
        return deferred

    def _op_migrate_cb(self, info, req):
        print '_op_migrate_cb>', info, req
        #req.setResponseCode(http.ACCEPTED)
        host = info.dst_host
        port = info.dst_port
        dom  = info.dst_dom
        url = "http://%s:%d/xend/domain/%d" % (host, port, dom)
        req.setHeader("Location", url)
        print '_op_migrate_cb> url=', url
        return url

    def _op_migrate_err(self, err, req):
        print '_op_migrate_err>', err, req
        req.setResponseCode(http.BAD_REQUEST, "Error: "+ str(err))
        return str(err)

    def op_pincpu(self, op, req):
        fn = FormFn(self.xd.domain_pincpu,
                    [['dom', 'str'],
                     ['cpu', 'int']])
        val = fn(req.args, {'dom': self.dom.id})
        return val

    def op_cpu_bvt_set(self, op, req):
        fn = FormFn(self.xd.domain_cpu_bvt_set,
                    [['dom', 'str'],
                     ['mcuadv', 'int'],
                     ['warpback', 'int'],
                     ['warpvalue', 'int'],
                     ['warpl', 'long'],
                     ['warpu', 'long']])
        val = fn(req.args, {'dom': self.dom.id})
        return val
    
    def op_cpu_atropos_set(self, op, req):
        fn = FormFn(self.xd.domain_cpu_atropos_set,
                    [['dom', 'str'],
                     ['period', 'int'],
                     ['slice', 'int'],
                     ['latency', 'int'],
                     ['xtratime', 'int']])
        val = fn(req.args, {'dom': self.dom.id})
        return val

    def op_maxmem_set(self, op, req):
        fn = FormFn(self.xd.domain_maxmem_set,
                    [['dom', 'str'],
                     ['memory', 'int']])
        val = fn(req.args, {'dom': self.dom.id})
        return val

    def op_device_create(self, op, req):
        fn = FormFn(self.xd.domain_device_create,
                    [['dom', 'str'],
                     ['config', 'sxpr']])
        d = fn(req.args, {'dom': self.dom.id})
        return d

    def op_device_destroy(self, op, req):
        fn = FormFn(self.xd.domain_device_destroy,
                    [['dom', 'str'],
                     ['type', 'str'],
                     ['idx', 'str']])
        val = fn(req.args, {'dom': self.dom.id})
        return val
                
    def op_device_configure(self, op, req):
        fn = FormFn(self.xd.domain_device_configure,
                    [['dom', 'str'],
                     ['config', 'sxpr'],
                     ['idx', 'str']])
        d = fn(req.args, {'dom': self.dom.id})
        return d

    def op_vifs(self, op, req):
        devs = self.xd.domain_vif_ls(self.dom.id)
        return [ dev.sxpr() for dev in devs ]

    def op_vif(self, op, req):
        fn = FormFn(self.xd.domain_vif_get,
                    [['dom', 'str'],
                     ['vif', 'str']])
        val = fn(req.args, {'dom': self.dom.id})
        return val

    def op_vbds(self, op, req):
        devs = self.xd.domain_vbd_ls(self.dom.id)
        return [ dev.sxpr() for dev in devs ]

    def op_vbd(self, op, req):
        fn = FormFn(self.xd.domain_vbd_get,
                    [['dom', 'str'],
                     ['vbd', 'str']])
        val = fn(req.args, {'dom': self.dom.id})
        return val

    def op_mem_target_set(self, op, req):
        fn = FormFn(self.xd.domain_mem_target_set,
                    [['dom', 'str'],
                     ['target', 'int']])
        val = fn(req.args, {'dom': self.dom.id})
        return val

    def render_POST(self, req):
        return self.perform(req)
        
    def render_GET(self, req):
        op = req.args.get('op')
        if op and op[0] in ['vifs', 'vif', 'vbds', 'vbd', 'mem_target_set']:
            return self.perform(req)
        if self.use_sxp(req):
            req.setHeader("Content-Type", sxp.mime_type)
            sxp.show(self.dom.sxpr(), out=req)
        else:
            req.write('<html><head></head><body>')
            self.print_path(req)
            #self.ls()
            req.write('<p>%s</p>' % self.dom)
            if self.dom.console:
                cinfo = self.dom.console
                cid = str(cinfo.console_port)
                #todo: Local xref: need to know server prefix.
                req.write('<p><a href="/xend/console/%s">Console %s</a></p>'
                          % (cid, cid))
                req.write('<p><a href="%s">Connect to console</a></p>'
                          % cinfo.uri())
            if self.dom.config:
                req.write("<code><pre>")
                PrettyPrint.prettyprint(self.dom.config, out=req)
                req.write("</pre></code>")
            self.form(req)
            req.write('</body></html>')
        return ''

    def form(self, req):
        url = req.prePathURL()
        req.write('<form method="post" action="%s">' % url)
        req.write('<input type="submit" name="op" value="unpause">')
        req.write('<input type="submit" name="op" value="pause">')
        req.write('</form>')

        req.write('<form method="post" action="%s">' % url)
        req.write('<input type="submit" name="op" value="destroy">')
        req.write('<input type="radio" name="reason" value="halt" checked>Halt')
        req.write('<input type="radio" name="reason" value="reboot">Reboot')
        req.write('</form>')

        req.write('<form method="post" action="%s">' % url)
        req.write('<input type="submit" name="op" value="shutdown">')
        req.write('<input type="radio" name="reason" value="poweroff" checked>Poweroff')
        req.write('<input type="radio" name="reason" value="halt">Halt')
        req.write('<input type="radio" name="reason" value="reboot">Reboot')
        req.write('</form>')
        
        req.write('<form method="post" action="%s">' % url)
        req.write('<br><input type="submit" name="op" value="save">')
        req.write(' To file: <input type="text" name="file">')
        req.write('</form>')
        
        req.write('<form method="post" action="%s">' % url)
        req.write('<br><input type="submit" name="op" value="migrate">')
        req.write(' To host: <input type="text" name="destination">')
        req.write('<input type="checkbox" name="live" value="1">Live')
        req.write('</form>')
