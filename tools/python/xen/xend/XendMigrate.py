# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import sys
import socket
import time

from twisted.internet import reactor
from twisted.internet import defer
defer.Deferred.debug = 1
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import ClientFactory

import sxp
import XendDB
import EventServer; eserver = EventServer.instance()

XFRD_PORT = 8002

XFR_PROTO_MAJOR = 1
XFR_PROTO_MINOR = 0

class Migrate(Protocol):

    def __init__(self, minfo):
        self.parser = sxp.Parser()
        self.minfo = minfo

    def connectionMade(self):
        # Send hello.
        self.request(['xfr.hello', XFR_PROTO_MAJOR, XFR_PROTO_MINOR])
        # Send migrate.
        vmconfig = self.minfo.vmconfig()
        if not vmconfig:
            self.loseConnection()
            return
        self.request(['xfr.migrate',
                      self.minfo.src_dom,
                      vmconfig,
                      self.minfo.dst_host,
                      self.minfo.dst_port])

    def request(self, req):
        sxp.show(req, out=self.transport)
        self.transport.write(' \n')

    def loseConnection(self):
        self.transport.loseConnection()

    def connectionLost(self, reason):
        self.minfo.closed(reason)

    def dispatch(self, val):
        op = sxp.name(val)
        op = op.replace('.', '_')
        if op.startswith('xfr_'):
            fn = getattr(self, op, self.unknown)
        else:
            fn = self.unknown()
        fn(val)

    def dataReceived(self, data):
        self.parser.input(data)
        if self.parser.ready():
            val = self.parser.get_val()
            self.dispatch(val)
        if self.parser.at_eof():
            self.loseConnection()
            
    def unknown(self, val):
        print 'unknown>', val

    def xfr_progress(self, val):
        print 'xfr_progress>', val

    def xfr_err(self, val):
        # If we get an error with non-zero code the migrate failed.
        # An error with code zero indicates hello success.
        print 'xfr_err>', val
        v = sxp.child(val)
        print 'xfr_err>', type(v), v
        err = int(sxp.child(val))
        if not err: return
        self.minfo.error(err);
        self.loseConnection()

    def xfr_ok(self, val):
        # An ok indicates migrate completed successfully, and contains
        # the new domain id on the remote system.
        print 'xfr_ok>', val
        dom = int(sxp.child(val))
        self.minfo.ok(dom)
        self.loseConnection()

class MigrateClientFactory(ClientFactory):

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


class XendMigrateInfo:

    # states: begin, active, failed, succeeded?

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
        
    def set_state(self, state):
        self.state = state

    def get_state(self):
        return self.state

    def sxpr(self):
        sxpr = ['migrate', ['id', self.id], ['state', self.state] ]
        sxpr_src = ['src', ['host', self.src_host], ['domain', self.src_dom] ]
        sxpr.append(sxpr_src)
        sxpr_dst = ['dst', ['host', self.dst_host] ]
        if self.dst_dom:
            sxpr_dst.append(['domain', self.dst_dom])
        sxpr.append(sxpr_dst)
        return sxpr

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

    def ok(self, dom):
        self.state = 'ok'
        self.dst_dom = dom

    def closed(self, reason=None):
        if self.state =='ok':
            eserver.inject('xend.migrate.ok', self.sxpr())
        else:
            self.state = 'error'
            eserver.inject('xend.migrate.error', self.sxpr())

class XendMigrate:
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
        mcf = MigrateClientFactory(info)
        reactor.connectTCP('localhost', XFRD_PORT, mcf)
        return info

def instance():
    global inst
    try:
        inst
    except:
        inst = XendMigrate()
    return inst
