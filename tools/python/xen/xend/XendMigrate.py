# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

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

XFRD_PORT = 8002

XFR_PROTO_MAJOR = 1
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
            self.xinfo.dispatch(val)
        if self.parser.at_eof():
            self.loseConnection()
            

class XfrdClientFactory(ClientFactory):
    """Factory for clients of the migration/save daemon xfrd.
    """

    def __init__(self, minfo):
        #ClientFactory.__init__(self)
        self.minfo = minfo

    def startedConnecting(self, connector):
        print 'Started to connect', 'self=', self, 'connector=', connector

    def buildProtocol(self, addr):
        print 'buildProtocol>', addr
        return Migrate(self.minfo)

    def clientConnectionLost(self, connector, reason):
        print 'clientConnectionLost>', 'connector=', connector, 'reason=', reason

    def clientConnectionFailed(self, connector, reason):
        print 'clientConnectionFailed>', 'connector=', connector, 'reason=', reason

class XfrdInfo:
    """Abstract class for info about a session with xfrd.
    Has subclasses for save and migrate.
    """
    
    def vmconfig(self):
        print 'vmconfig>'
        from xen.xend import XendDomain
        xd = XendDomain.instance()

        dominfo = xd.domain_get(self.src_dom)
        print 'vmconfig>', type(dominfo), dominfo
        if dominfo:
            val = sxp.to_string(dominfo.sxpr())
        else:
            val = None
        print 'vmconfig<', 'val=', type(val), val
        return val

    def error(self, err):
        self.state = 'error'

    def dispatch(self, xfrd, val):
        op = sxp.name(val)
        op = op.replace('.', '_')
        if op.startswith('xfr_'):
            fn = getattr(self, op, self.unknown)
        else:
            fn = self.unknown()
        fn(xfrd, val)

    def unknown(self, xfrd, val):
        print 'unknown>', val

    def xfr_err(self, xfrd, val):
        # If we get an error with non-zero code the migrate failed.
        # An error with code zero indicates hello success.
        print 'xfr_err>', val
        v = sxp.child(val)
        print 'xfr_err>', type(v), v
        err = int(sxp.child(val))
        if not err: return
        self.error(err);
        xfrd.loseConnection()

    def xfr_progress(self, val):
        print 'xfr_progress>', val

    def xfr_domain_pause(self, val):
        print 'xfr__domain_pause>', val

    def xfr_domain_suspend(self, val):
        print 'xfr_domain_suspend>', val

class XendMigrateInfo(XfrdInfo):
    """Representation of a migrate in-progress and its interaction with xfrd.
    """

    def __init__(self, id, dom, host, port):
        self.id = id
        self.state = 'begin'
        self.src_host = socket.gethostname()
        self.src_dom = dom
        self.dst_host = host
        self.dst_port = port
        self.dst_dom = None
        self.start = 0
        self.deferred = defer.Deferred()
        
    def sxpr(self):
        sxpr = ['migrate', ['id', self.id], ['state', self.state] ]
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
                      self.d.dst_port])
        
    def xfr_migrate_ok(self, val):
        dom = int(sxp.child0(val))
        self.state = 'ok'
        self.dst_dom = dom

    def connectionLost(self, reason=None):
        if self.state =='ok':
            eserver.inject('xend.migrate.ok', self.sxpr())
        else:
            self.state = 'error'
            eserver.inject('xend.migrate.error', self.sxpr())

class XendSaveInfo(XfrdInfo):
    """Representation of a save in-progress and its interaction with xfrd.
    """
    
    def __init__(self, id, dom, file):
        self.id = id
        self.state = 'begin'
        self.src_dom = dom
        self.file = file
        self.start = 0
        self.deferred = defer.Deferred()
        
    def sxpr(self):
        sxpr = ['save',
                ['id', self.id],
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
    # Represents migration in progress.
    # Use log for indications of begin/end/errors?
    # Need logging of: domain create/halt, migrate begin/end/fail
    # Log via event server?

    dbpath = "migrate"
    
    def __init__(self):
        self.db = XendDB.XendDB(self.dbpath)
        self.migrate = {}
        self.migrate_db = self.db.fetchall("")
        self.id = 0

    def nextid(self):
        self.id += 1
        return "%d" % self.id

    def sync(self):
        self.db.saveall("", self.migrate_db)

    def sync_migrate(self, id):
        self.db.save(id, self.migrate_db[id])

    def close(self):
        pass

    def _add_migrate(self, id, info):
        self.migrate[id] = info
        self.migrate_db[id] = info.sxpr()
        self.sync_migrate(id)
        #eserver.inject('xend.migrate.begin', info.sxpr())

    def _delete_migrate(self, id):
        #eserver.inject('xend.migrate.end', id)
        del self.migrate[id]
        del self.migrate_db[id]
        self.db.delete(id)

    def migrate_ls(self):
        return self.migrate.keys()

    def migrates(self):
        return self.migrate.values()

    def migrate_get(self, id):
        return self.migrate.get(id)
    
    def migrate_begin(self, dom, host, port=XFRD_PORT):
        # Check dom for existence, not migrating already.
        # Subscribe to migrate notifications (for updating).
        id = self.nextid()
        info = XendMigrateInfo(id, dom, host, port)
        self._add_migrate(id, info)
        mcf = XfrdClientFactory(info)
        reactor.connectTCP('localhost', XFRD_PORT, mcf)
        return info

def instance():
    global inst
    try:
        inst
    except:
        inst = XendMigrate()
    return inst
