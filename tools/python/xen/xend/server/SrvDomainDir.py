# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import traceback
from StringIO import StringIO

from twisted.protocols import http
from twisted.web import error

from xen.xend import sxp
from xen.xend import XendDomain
from xen.xend.Args import FormFn

from SrvDir import SrvDir
from SrvDomain import SrvDomain

class SrvDomainDir(SrvDir):
    """Service that manages the domain directory.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.xd = XendDomain.instance()

    def domain(self, x):
        val = None
        try:
            dom = self.xd.domain_get(x)
            if not dom: raise KeyError('No such domain')
            val = SrvDomain(dom)
        except KeyError, ex:
            print 'SrvDomainDir>', ex
            pass
        return val

    def get(self, x):
        v = SrvDir.get(self, x)
        if v is not None:
            return v
        v = self.domain(x)
        return v

    def op_create(self, op, req):
        """Create a domain.
        Expects the domain config in request parameter 'config' in SXP format.
        """
        ok = 0
        try:
            configstring = req.args.get('config')[0]
            print 'config:', configstring
            pin = sxp.Parser()
            pin.input(configstring)
            pin.input_eof()
            config = pin.get_val()
            ok = 1
        except Exception, ex:
            print 'op_create> Exception in config', ex
            traceback.print_exc()
        if not ok:
            req.setResponseCode(http.BAD_REQUEST, "Invalid configuration")
            return "Invalid configuration"
            return error.ErrorPage(http.BAD_REQUEST,
                                   "Invalid",
                                   "Invalid configuration")
        try:
            deferred = self.xd.domain_create(config)
            deferred.addCallback(self._op_create_cb, configstring, req)
            deferred.addErrback(self._op_create_err, req)
            return deferred
        except Exception, ex:
            print 'op_create> Exception creating domain:'
            traceback.print_exc()
            req.setResponseCode(http.BAD_REQUEST, "Error creating domain: " + str(ex))
            return str(ex)
            #return error.ErrorPage(http.BAD_REQUEST,
            #                       "Error creating domain",
            #                       str(ex))
                                   

    def _op_create_cb(self, dominfo, configstring, req):
        """Callback to handle deferred domain creation.
        """
        dom = dominfo.id
        domurl = "%s/%s" % (req.prePathURL(), dom)
        req.setResponseCode(201, "created")
        req.setHeader("Location", domurl)
        if self.use_sxp(req):
            return dominfo.sxpr()
        else:
            out = StringIO()
            print >> out, ('<p> Created <a href="%s">Domain %s</a></p>'
                           % (domurl, dom))
            print >> out, '<p><pre>'
            print >> out, configstring
            print >> out, '</pre></p>'
            val = out.getvalue()
            out.close()
            return val

    def _op_create_err(self, err, req):
        """Callback to handle errors in deferred domain creation.
        """
        print 'op_create> Deferred Exception creating domain:', err
        req.setResponseCode(http.BAD_REQUEST, "Error creating domain: " + str(err))
        return str(err)

    def op_restore(self, op, req):
        """Restore a domain from file.
        """
        fn = FormFn(self.xd.domain_restore,
                    [['file', 'str']])
        val = fn(req.args)
        return val
        
    def render_POST(self, req):
        return self.perform(req)

    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-Type", sxp.mime_type)
            self.ls_domain(req, 1)
        else:
            req.write("<html><head></head><body>")
            self.print_path(req)
            self.ls(req)
            self.ls_domain(req)
            self.form(req)
            req.write("</body></html>")
        return ''

    def ls_domain(self, req, use_sxp=0):
        url = req.prePathURL()
        if not url.endswith('/'):
            url += '/'
        if use_sxp:
            domains = self.xd.domain_ls()
            sxp.show(domains, out=req)
        else:
            domains = self.xd.domains()
            domains.sort(lambda x, y: cmp(x.id, y.id))
            req.write('<ul>')
            for d in domains:
               req.write('<li><a href="%s%s"> Domain %s</a>'
                         % (url, d.id, d.id))
               req.write('name=%s' % d.name)
               req.write('memory=%d'% d.memory)
               req.write('</li>')
            req.write('</ul>')

    def form(self, req):
        """Generate the form(s) for domain dir operations.
        """
        req.write('<form method="post" action="%s" enctype="multipart/form-data">'
                  % req.prePathURL())
        req.write('<button type="submit" name="op" value="create">Create Domain</button>')
        req.write('Config <input type="file" name="config"><br>')
        req.write('</form>')
        req.write('<form method="post" action="%s" enctype="multipart/form-data">'
                  % req.prePathURL())
        req.write('<button type="submit" name="op" value="create">Restore Domain</button>')
        req.write('State <input type="string" name="state"><br>')
        req.write('</form>')
        
