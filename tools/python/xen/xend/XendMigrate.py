# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import errno
import sys
import socket
import time

from twisted.internet import reactor
from twisted.internet import defer
#defer.Deferred.debug = 1
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import ClientFactory

import sxp
import XendDB
import EventServer; eserver = EventServer.instance()

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

    def connectionMade(self):
        # Send hello.
        self.request(['xfr.hello', XFR_PROTO_MAJOR, XFR_PROTO_MINOR])
        # Send request.
        self.xinfo.request(self)

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

    def startedConnecting(self, connector):
        print 'Started to connect', 'self=', self, 'connector=', connector

    def buildProtocol(self, addr):
        print 'buildProtocol>', addr
        return Xfrd(self.xinfo)

    def clientConnectionLost(self, connector, reason):
        print 'clientConnectionLost>', 'connector=', connector, 'reason=', reason

    def clientConnectionFailed(self, connector, reason):
        print 'clientConnectionFailed>', 'connector=', connector, 'reason=', reason

class XfrdInfo:
    """Abstract class for info about a session with xfrd.
    Has subclasses for save and migrate.
    """

    def __init__(self):
        from xen.xend import XendDomain
        self.xd = XendDomain.instance()
        self.deferred = defer.Deferred()
        
    def vmconfig(self):
        print 'vmconfig>'
        dominfo = self.xd.domain_get(self.src_dom)
        print 'vmconfig>', type(dominfo), dominfo
        if dominfo:
            val = sxp.to_string(dominfo.sxpr())
        else:
            val = None
        print 'vmconfig<', 'val=', type(val), val
        return val

    def error(self, err):
        self.state = 'error'
        if not self.deferred.called:
            self.deferred.errback(err)

    def dispatch(self, xfrd, val):
        op = sxp.name(val)
        op = op.replace('.', '_')
        if op.startswith('xfr_'):
            fn = getattr(self, op, self.unknown)
        else:
            fn = self.unknown
        val = fn(xfrd, val)
        if val is not None:
            sxp.show(val, out=self.transport)

    def unknown(self, xfrd, val):
        print 'unknown>', val
        xfrd.loseConnection()
        return None

    def xfr_err(self, xfrd, val):
        # If we get an error with non-zero code the operation failed.
        # An error with code zero indicates hello success.
        print 'xfr_err>', val
        v = sxp.child0(val)
        print 'xfr_err>', type(v), v
        err = int(sxp.child0(val))
        if not err: return
        self.error(err);
        xfrd.loseConnection()
        #try:
        #    self.xd.domain_unpause(self.src_dom)
        #except:
        #    print >>sys.stdout, "Error unpausing domain:", self.src_dom
        return None

    def xfr_progress(self, xfrd, val):
        print 'xfr_progress>', val
        return None

    def xfr_vm_pause(self, xfrd, val):
        print 'xfr_vm_pause>', val
        try:
            vmid = sxp.child0(val)
            val = self.xd.domain_pause(vmid)
        except:
            val = errno.EINVAL
        return ['xfr.err', val]

    def xfr_vm_unpause(self, xfrd, val):
        print 'xfr_vm_unpause>', val
        try:
            vmid = sxp.child0(val)
            val = self.xd.domain_unpause(vmid)
        except:
            val = errno.EINVAL
        return ['xfr.err', val]

    def xfr_vm_suspend(self, xfrd, val):
        print 'xfr_vm_suspend>', val
        try:
            vmid = sxp.child0(val)
            val = self.xd.domain_shutdown(vmid, reason='suspend')
        except:
            val = errno.EINVAL
        return ['xfr.err', val]

class XendMigrateInfo(XfrdInfo):
    """Representation of a migrate in-progress and its interaction with xfrd.
    """

    def __init__(self, xid, dom, host, port):
        XfrdInfo.__init__(self)
        self.xid = xid
        self.state = 'begin'
        self.src_host = socket.gethostname()
        self.src_dom = dom
        self.dst_host = host
        self.dst_port = port
        self.dst_dom = None
        self.start = 0
        
    def sxpr(self):
        sxpr = ['migrate', ['id', self.xid], ['state', self.state] ]
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
            xfrd.loseConnection()
            return
        xfrd.request(['xfr.migrate',
                      self.src_dom,
                      vmconfig,
                      self.dst_host,
                      self.dst_port])
        
    def xfr_migrate_ok(self, val):
        dom = int(sxp.child0(val))
        self.state = 'ok'
        self.dst_dom = dom
        self.xd_domain_destroy(self.src_dom)
        if not self.deferred.called:
            self.deferred.callback(self)

    def connectionLost(self, reason=None):
        if self.state =='ok':
            eserver.inject('xend.migrate.ok', self.sxpr())
        else:
            self.state = 'error'
            eserver.inject('xend.migrate.error', self.sxpr())

class XendSaveInfo(XfrdInfo):
    """Representation of a save in-progress and its interaction with xfrd.
    """
    
    def __init__(self, xid, dom, file):
        XfrdInfo.__init__(self)
        self.xid = xid
        self.state = 'begin'
        self.src_dom = dom
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
            xfrd.loseConnection()
            return
        xfrd.request(['xfr.save', self.src_dom, vmconfig, self.file ])
        
    def xfr_save_ok(self, val):
        dom = int(sxp.child0(val))
        self.state = 'ok'
        self.xd_domain_destroy(self.src_dom)
        if not self.deferred.called:
            self.deferred.callback(self)

    def connectionLost(self, reason=None):
        if self.state =='ok':
            eserver.inject('xend.save.ok', self.sxpr())
        else:
            self.state = 'error'
            eserver.inject('xend.save.error', self.sxpr())
    

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
        print 'sync_session>', type(xid), xid, self.session_db[xid]
        self.db.save(xid, self.session_db[xid])

    def close(self):
        pass

    def _add_session(self, xid, info):
        self.session[xid] = info
        self.session_db[xid] = info.sxpr()
        self.sync_session(xid)
        #eserver.inject('xend.migrate.begin', info.sxpr())

    def _delete_session(self, xid):
        #eserver.inject('xend.migrate.end', xid)
        del self.session[xid]
        del self.session_db[xid]
        self.db.delete(xid)

    def session_ls(self):
        return self.session.keys()

    def sessions(self):
        return self.session.values()

    def session_get(self, xid):
        return self.session.get(xid)

    def session_begin(self, info):
        self._add_session(info.xid, info)
        mcf = XfrdClientFactory(info)
        reactor.connectTCP('localhost', XFRD_PORT, mcf)
        return info
    
    def migrate_begin(self, dom, host, port=XFRD_PORT):
        """Begin to migrate a domain to another host.

        @param dom:  domain
        @param host: destination host
        @param port: destination port
        @return: deferred
        """
        # Check dom for existence, not migrating already.
        # Subscribe to migrate notifications (for updating).
        xid = self.nextid()
        info = XendMigrateInfo(xid, dom, host, port)
        self.session_begin(info)
        return info.deferred

    def save_begin(self, dom, file):
        """Begin saving a domain to file.

        @param dom:  domain
        @param file: destination file
        @return: deferred
        """
        xid = self.nextid()
        info = XendSaveInfo(xid, dom, file)
        self.session_begin(info)
        return info.deferred

def instance():
    global inst
    try:
        inst
    except:
        inst = XendMigrate()
    return inst
