# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import traceback
import threading

import errno
import sys
import socket
import time
import types

from xen.web import reactor
from xen.web.protocol import Protocol, ClientFactory

import sxp
import XendDB
import EventServer; eserver = EventServer.instance()
from XendError import XendError
from XendLogging import log
        
"""The port for the migrate/save daemon xfrd."""
XFRD_PORT = 8002

"""The transfer protocol major version number."""
XFR_PROTO_MAJOR = 1
"""The transfer protocol minor version number."""
XFR_PROTO_MINOR = 0

class Xfrd(Protocol):
    """Protocol handler for a connection to the migration/save daemon xfrd.
    """

    def __init__(self, xinfo):
        self.parser = sxp.Parser()
        self.xinfo = xinfo

    def connectionMade(self, addr=None):
        # Send hello.
        self.request(['xfr.hello', XFR_PROTO_MAJOR, XFR_PROTO_MINOR])
        # Send request.
        self.xinfo.request(self)
        # Run the transport mainLoop which reads from the peer.
        self.transport.mainLoop()

    def request(self, req):
        sxp.show(req, out=self.transport)

    def loseConnection(self):
        self.transport.loseConnection()

    def connectionLost(self, reason):
        self.xinfo.connectionLost(reason)

    def dataReceived(self, data):
        self.parser.input(data)
        if self.parser.ready():
            val = self.parser.get_val()
            self.xinfo.dispatch(self, val)
        if self.parser.at_eof():
            self.loseConnection()
            
class XfrdClientFactory(ClientFactory):
    """Factory for clients of the migration/save daemon xfrd.
    """

    def __init__(self, xinfo):
        #ClientFactory.__init__(self)
        self.xinfo = xinfo
        self.readyCond = threading.Condition()
        self.ready = False
        self.err = None

    def start(self):
        print 'XfrdClientFactory>start>'
        reactor.connectTCP('localhost', XFRD_PORT, self)
        try:
            self.readyCond.acquire()
            while not self.ready:
                self.readyCond.wait()
        finally:
            self.readyCond.release()
        print 'XfrdClientFactory>start>', 'err=', self.err
        if self.err:
            raise self.err
        return 0

    def notifyReady(self):
        try:
            self.readyCond.acquire()
            self.ready = True
            self.err = self.xinfo.error_summary()
            self.readyCond.notify()
        finally:
            self.readyCond.release()
            
    def startedConnecting(self, connector):
        pass

    def buildProtocol(self, addr):
        return Xfrd(self.xinfo)

    def clientConnectionLost(self, connector, reason):
        print "XfrdClientFactory>clientConnectionLost>", reason
        self.notifyReady()

    def clientConnectionFailed(self, connector, reason):
        print "XfrdClientFactory>clientConnectionFailed>", reason
        self.xinfo.error(reason)
        self.notifyReady()

class SuspendHandler:

    def __init__(self, xinfo, vmid, timeout):
        self.xinfo = xinfo
        self.vmid = vmid
        self.timeout = timeout
        self.readyCond = threading.Condition()
        self.ready = False
        self.err = None

    def start(self):
        self.subscribe(on=True)
        timer = reactor.callLater(self.timeout, self.onTimeout)
        try:
            self.readyCond.acquire()
            while not self.ready:
                self.readyCond.wait()
        finally:
            self.readyCond.release()
            self.subscribe(on=False)
            timer.cancel()
        if self.err:
            raise XendError(self.err)

    def notifyReady(self, err=None):
        try:
            self.readyCond.acquire()
            if not self.ready:
                self.ready = True
                self.err = err
                self.readyCond.notify()
        finally:
            self.readyCond.release()

    def subscribe(self, on=True):
        # Subscribe to 'suspended' events so we can tell when the
        # suspend completes. Subscribe to 'died' events so we can tell if
        # the domain died.
        if on:
            action = eserver.subscribe
        else:
            action = eserver.unsubscribe
        action('xend.domain.suspended', self.onSuspended)
        action('xend.domain.died', self.onDied)

    def onSuspended(self, e, v):
        if v[1] != self.vmid: return
        print 'SuspendHandler>onSuspended>', e, v
        self.notifyReady()
                
    def onDied(self, e, v):
        if v[1] != self.vmid: return
        print 'SuspendHandler>onDied>', e, v
        self.notifyReady('Domain %s died while suspending' % self.vmid)

    def onTimeout(self):
         print 'SuspendHandler>onTimeout>'
         self.notifyReady('Domain %s suspend timed out' % self.vmid)

class XfrdInfo:
    """Abstract class for info about a session with xfrd.
    Has subclasses for save and migrate.
    """

    """Suspend timeout (seconds).
    We set a timeout because suspending a domain can hang."""
    timeout = 30

    def __init__(self):
        from xen.xend import XendDomain
        self.xd = XendDomain.instance()
        self.suspended = {}
        self.paused = {}
        self.state = 'init'
        # List of errors encountered.
        self.errors = []
            
    def vmconfig(self):
        dominfo = self.xd.domain_get(self.src_dom)
        if dominfo:
            val = sxp.to_string(dominfo.sxpr())
        else:
            val = None
        return val

    def add_error(self, err):
        """Add an error to the error list.
        Returns the error added.
        """
        if err not in self.errors:
            self.errors.append(err)
        return err

    def error_summary(self, msg=None):
        """Get a XendError summarising the errors (if any).
        """
        if not self.errors:
            return None
        if msg is None:
            msg = "errors"
        if self.errors:
            errmsg = msg + ': ' + ', '.join(map(str, self.errors))
        else:
            errmsg = msg
        return XendError(errmsg)

    def get_errors(self):
        """Get the list of errors.
        """
        return self.errors

    def error(self, err):
        print 'XfrdInfo>error>', err
        self.state = 'error'
        self.add_error(err)

    def dispatch(self, xfrd, val):
        print 'XfrdInfo>dispatch>', val
        op = sxp.name(val)
        op = op.replace('.', '_')
        if op.startswith('xfr_'):
            fn = getattr(self, op, self.unknown)
        else:
            fn = self.unknown
        try:
            val = fn(xfrd, val)
            if val:
                sxp.show(val, out=xfrd.transport)
        except Exception, err:
            print 'XfrdInfo>dispatch> error:', err
            val = ['xfr.err', errno.EINVAL]
            sxp.show(val, out=xfrd.transport)
            self.error(err)

    def unknown(self, xfrd, val):
        xfrd.loseConnection()
        return None

    def xfr_err(self, xfrd, val):
        # If we get an error with non-zero code the operation failed.
        # An error with code zero indicates hello success.
        print 'XfrdInfo>xfr_err>', val
        v = sxp.child0(val)
        err = int(sxp.child0(val))
        if not err: return
        self.error("transfer daemon (xfrd) error: " + str(err))
        xfrd.loseConnection()
        return None

    def xfr_progress(self, xfrd, val):
        return None

    def xfr_vm_destroy(self, xfrd, val):
        try:
            vmid = sxp.child0(val)
            val = self.xd.domain_destroy(vmid)
            if vmid in self.paused:
                del self.paused[vmid]
            if vmid in self.suspended:
                del self.suspended[vmid]
        except StandardError, err:
            self.add_error("vm_destroy failed")
            self.add_error(err)
            val = errno.EINVAL
        return ['xfr.err', val]
    
    def xfr_vm_pause(self, xfrd, val):
        try:
            vmid = sxp.child0(val)
            val = self.xd.domain_pause(vmid)
            self.paused[vmid] = 1
        except StandardError, err:
            self.add_error("vm_pause failed")
            self.add_error(err)
            val = errno.EINVAL
        return ['xfr.err', val]

    def xfr_vm_unpause(self, xfrd, val):
        try:
            vmid = sxp.child0(val)
            val = self.xd.domain_unpause(vmid)
            if vmid in self.paused:
                del self.paused[vmid]
        except StandardError, err:
            self.add_error("vm_unpause failed")
            self.add_error(err)
            val = errno.EINVAL
        return ['xfr.err', val]

    def xfr_vm_suspend(self, xfrd, val):
        """Suspend a domain.
        Suspending can hang, so we set a timeout and fail if it
        takes too long.
        """
        try:
            vmid = sxp.child0(val)
            h = SuspendHandler(self, vmid, self.timeout)
            val = self.xd.domain_shutdown(vmid, reason='suspend')
            self.suspended[vmid] = 1
            h.start()
            print 'xfr_vm_suspend> suspended', vmid
        except Exception, err:
            print 'xfr_vm_suspend> err', err
            self.add_error("suspend failed")
            self.add_error(err)
            traceback.print_exc()
            val = errno.EINVAL
        return ['xfr.err', val]

    def connectionLost(self, reason=None):
        print 'XfrdInfo>connectionLost>', reason
        for vmid in self.suspended:
            try:
                self.xd.domain_destroy(vmid)
            except:
                pass
        for vmid in self.paused:
            try:
                self.xd.domain_unpause(vmid)
            except:
                pass

class XendMigrateInfo(XfrdInfo):
    """Representation of a migrate in-progress and its interaction with xfrd.
    """

    def __init__(self, xid, dominfo, host, port, live=0, resource=0):
        XfrdInfo.__init__(self)
        self.xid = xid
        self.dominfo = dominfo
        self.state = 'begin'
        self.src_host = socket.gethostname()
        self.src_dom = dominfo.id
        self.dst_host = host
        self.dst_port = port
        self.dst_dom = None
        self.live = live
        self.resource = resource
        self.start = 0
        
    def sxpr(self):
        sxpr = ['migrate',
                ['id',    self.xid   ],
                ['state', self.state ],
                ['live',  self.live  ],
                ['resource', self.resource ] ]
        sxpr_src = ['src', ['host', self.src_host], ['domain', self.src_dom] ]
        sxpr.append(sxpr_src)
        sxpr_dst = ['dst', ['host', self.dst_host] ]
        if self.dst_dom:
            sxpr_dst.append(['domain', self.dst_dom])
        sxpr.append(sxpr_dst)
        return sxpr

    def request(self, xfrd):
        vmconfig = self.vmconfig()
        if not vmconfig:
            self.error(XendError("vm config not found"))
            xfrd.loseConnection()
            return
        log.info('Migrate BEGIN: %s' % str(self.sxpr()))
        eserver.inject('xend.domain.migrate',
                       [ self.dominfo.name, self.dominfo.id, "begin", self.sxpr() ])
        xfrd.request(['xfr.migrate',
                      self.src_dom,
                      vmconfig,
                      self.dst_host,
                      self.dst_port,
                      self.live,
                      self.resource ])
        
    def xfr_migrate_ok(self, xfrd, val):
        dom = int(sxp.child0(val))
        self.state = 'ok'
        self.dst_dom = dom
        self.xd.domain_destroy(self.src_dom)

    def connectionLost(self, reason=None):
        print 'XendMigrateInfo>connectionLost>', reason
        XfrdInfo.connectionLost(self, reason)
        if self.state =='ok':
            log.info('Migrate OK: ' + str(self.sxpr()))
        else:
            self.state = 'error'
            self.error("migrate failed")
            log.info('Migrate ERROR: ' + str(self.sxpr()))
        eserver.inject('xend.domain.migrate',
                       [ self.dominfo.name, self.dominfo.id, self.state, self.sxpr() ])

class XendSaveInfo(XfrdInfo):
    """Representation of a save in-progress and its interaction with xfrd.
    """
    
    def __init__(self, xid, dominfo, file):
        XfrdInfo.__init__(self)
        self.xid = xid
        self.dominfo = dominfo
        self.state = 'begin'
        self.src_dom = dominfo.id
        self.file = file
        self.start = 0
        
    def sxpr(self):
        sxpr = ['save',
                ['id', self.xid],
                ['state', self.state],
                ['domain', self.src_dom],
                ['file', self.file] ]
        return sxpr

    def request(self, xfrd):
        vmconfig = self.vmconfig()
        if not vmconfig:
            self.error(XendError("vm config not found"))
            xfrd.loseConnection()
            return
        log.info('Save BEGIN: ' + str(self.sxpr()))
        eserver.inject('xend.domain.save',
                       [ self.dominfo.name, self.dominfo.id,
                         "begin", self.sxpr() ])
        xfrd.request(['xfr.save', self.src_dom, vmconfig, self.file ])
        
    def xfr_save_ok(self, xfrd, val):
        self.state = 'ok'
        self.xd.domain_destroy(self.src_dom)

    def connectionLost(self, reason=None):
        print 'XendSaveInfo>connectionLost>', reason
        XfrdInfo.connectionLost(self, reason)
        if self.state =='ok':
            log.info('Save OK: ' + str(self.sxpr()))
        else:
            self.state = 'error'
            self.error("save failed")
            log.info('Save ERROR: ' + str(self.sxpr()))
        eserver.inject('xend.domain.save',
                       [ self.dominfo.name, self.dominfo.id,
                         self.state, self.sxpr() ])
    
class XendRestoreInfo(XfrdInfo):
    """Representation of a restore in-progress and its interaction with xfrd.
    """

    def __init__(self, xid, file):
        XfrdInfo.__init__(self)
        self.xid = xid
        self.state = 'begin'
        self.file = file

    def sxpr(self):
         sxpr = ['restore',
                 ['id', self.xid],
                 ['file', self.file] ]
         return sxpr

    def request(self, xfrd):
        log.info('restore BEGIN: ' + str(self.sxpr()))
        eserver.inject('xend.restore', [ 'begin', self.sxpr()])
                       
        xfrd.request(['xfr.restore', self.file ])
        
    def xfr_restore_ok(self, xfrd, val):
        dom = int(sxp.child0(val))
        dominfo = self.xd.domain_get(dom)
        self.state = 'ok'
         
    def connectionLost(self, reason=None):
        XfrdInfo.connectionLost(self, reason)
        if self.state =='ok':
            log.info('Restore OK: ' + self.file)
        else:
            self.state = 'error'
            self.error("restore failed")
            log.info('Restore ERROR: ' + str(self.sxpr()))
        eserver.inject('xend.restore', [ self.state,  self.sxpr()])

class XendMigrate:
    """External api for interaction with xfrd for migrate and save.
    Singleton.
    """
    # Use log for indications of begin/end/errors?
    # Need logging of: domain create/halt, migrate begin/end/fail
    # Log via event server?

    dbpath = "migrate"
    
    def __init__(self):
        self.db = XendDB.XendDB(self.dbpath)
        self.session = {}
        self.session_db = self.db.fetchall("")
        self.xid = 0

    def nextid(self):
        self.xid += 1
        return "%d" % self.xid

    def sync(self):
        self.db.saveall("", self.session_db)

    def sync_session(self, xid):
        self.db.save(xid, self.session_db[xid])

    def close(self):
        pass

    def _add_session(self, info):
        xid = info.xid
        self.session[xid] = info
        self.session_db[xid] = info.sxpr()
        self.sync_session(xid)

    def _delete_session(self, xid):
        if xid in self.session:
            del self.session[xid]
        if xid in self.session_db:
            del self.session_db[xid]
            self.db.delete(xid)

    def session_ls(self):
        return self.session.keys()

    def sessions(self):
        return self.session.values()

    def session_get(self, xid):
        return self.session.get(xid)

    def session_begin(self, info):
        """Add the session to the table and start it.
        Remove the session from the table when it finishes.

        @param info: session
        """
        self._add_session(info)
        try:
            xcf = XfrdClientFactory(info)
            return xcf.start()
        finally:
            self._delete_session(info.xid)
    
    def migrate_begin(self, dominfo, host, port=XFRD_PORT, live=0, resource=0):
        """Begin to migrate a domain to another host.

        @param dominfo:  domain info
        @param host: destination host
        @param port: destination port
        """
        xid = self.nextid()
        info = XendMigrateInfo(xid, dominfo, host, port, live, resource)
        return self.session_begin(info)

    def save_begin(self, dominfo, file):
        """Begin saving a domain to file.

        @param dominfo:  domain info
        @param file: destination file
        """
        xid = self.nextid()
        info = XendSaveInfo(xid, dominfo, file)
        return self.session_begin(info)

    def restore_begin(self, file):
        xid = self.nextid()
        info = XendRestoreInfo(xid, file)
        return self.session_begin(info)
        

def instance():
    global inst
    try:
        inst
    except:
        inst = XendMigrate()
    return inst
