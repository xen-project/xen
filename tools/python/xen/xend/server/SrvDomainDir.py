# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import traceback
from StringIO import StringIO

from twisted.protocols import http
from twisted.web import error

from xen.xend import sxp
from xen.xend import XendDomain
from xen.xend.Args import FormFn
from xen.xend.XendError import XendError

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
        dom = self.xd.domain_lookup(x)
        if not dom:
            raise XendError('No such domain ' + str(x))
        val = SrvDomain(dom)
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
        errmsg = ''
        try:
            configstring = req.args.get('config')[0]
            #print 'op_create>', 'config:', configstring
            pin = sxp.Parser()
            pin.input(configstring)
            pin.input_eof()
            config = pin.get_val()
            ok = 1
        except Exception, ex:
            print 'op_create> Exception in config', ex
            traceback.print_exc()
            errmsg = 'Configuration error ' + str(ex)
        except sxp.ParseError, ex:
            errmsg = 'Invalid configuration ' + str(ex)
        if not ok:
            req.setResponseCode(http.BAD_REQUEST, errmsg)
            return errmsg
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

    def _op_create_cb(self, dominfo, configstring, req):
        """Callback to handle deferred domain creation.
        """
        dom = dominfo.name
        domurl = "%s/%s" % (req.prePathURL(), dom)
        req.setResponseCode(http.CREATED, "created")
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

        @return: deferred
        """
        #todo: return is deferred. May need ok and err callbacks.
        fn = FormFn(self.xd.domain_restore,
                    [['file', 'str']])
        deferred = fn(req.args)
        deferred.addCallback(self._op_restore_cb, req)
        #deferred.addErrback(self._op_restore_err, req)
        return deferred

    def _op_restore_cb(self, dominfo, req):
        dom = dominfo.name
        domurl = "%s/%s" % (req.prePathURL(), dom)
        req.setResponseCode(http.CREATED)
        req.setHeader("Location", domurl)
        if self.use_sxp(req):
            return dominfo.sxpr()
        else:
            out = StringIO()
            print >> out, ('<p> Created <a href="%s">Domain %s</a></p>'
                           % (domurl, dom))
            val = out.getvalue()
            out.close()
            return val

    def _op_restore_err(self, err, req):
        print 'op_create> Deferred Exception restoring domain:', err
        req.setResponseCode(http.BAD_REQUEST, "Error restoring domain: "+ str(err))
        return str(err)
        
    def render_POST(self, req):
        return self.perform(req)

    def render_GET(self, req):
        try:
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
        except Exception, ex:
            self._perform_err(ex, req)

    def ls_domain(self, req, use_sxp=0):
        url = req.prePathURL()
        if not url.endswith('/'):
            url += '/'
        if use_sxp:
            domains = self.xd.domain_ls()
            sxp.show(domains, out=req)
        else:
            domains = self.xd.domains()
            domains.sort(lambda x, y: cmp(x.name, y.name))
            req.write('<ul>')
            for d in domains:
               req.write('<li><a href="%s%s"> Domain %s</a>'
                         % (url, d.name, d.name))
               req.write('id=%s' % d.id)
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
        req.write('<button type="submit" name="op" value="restore">Restore Domain</button>')
        req.write('State <input type="string" name="state"><br>')
        req.write('</form>')
        
