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

from xen.xend.packing import SxpPacker, SxpUnpacker
from xen.xend import XendDomain
xd = XendDomain.instance()


XFRD_PORT = 8002

XFR_PROTO_MAJOR = 1
XFR_PROTO_MINOR = 0

class Migrate(Protocol):

    def __init__(self, minfo):
        self.packer = None
        self.unpacker = None
        self.minfo = minfo

    def connectionMade(self):
        self.packer = SxpPacker(self.transport)
        self.unpacker = SxpPacker()
        # Send hello.
        self.packer.pack(['xfr.hello', XFR_PROTO_MAJOR, XFR_PROTO_MINOR])
        # Send migrate.
        vmconfig = self.minfo.vmconfig()
        if not vmconfig:
            self.loseConnection()
            return
        self.packer.pack(['xfr.migrate',
                          self.minfo.src_dom,
                          vmconfig,
                          self.minfo.dst_host,
                          self.minfo.dst_port])

    def connectionLost(self, reason):
        self.minfo.closed(reason)

    def dataReceived(self, data):
        try:
            self.unpacker.reset(data)
            val = self.unpacker.unpack()
            print 'dataReceived>', 'val=', val
            op = val[0]
            op.replace('.', '_')
            if op.startwith('xfr_'):
                fn = getattr(self, op, self.unknown)
            else:
                fn = self.unknown
            fn(val)
        except Exception, ex:
            print 'dataReceived>', ex
            pass

    def unknown(self, val):
        print 'unknown>', val

    def xfr_progress(self, val):
        print 'xfr_progress>', val

    def xfr_error(self, val):
        # If we get an error with non-zero code the migrate failed.
        # An error with code zero indicates hello success.
        err = int(val[1])
        if not err: return
        self.minfo.error(err);
        self.loseConnection()

    def xfr_ok(self, val):
        # An ok indicates migrate completed successfully, and contains
        # the new domain id on the remote system.
        dom = int(val[1])
        self.minfo.ok(dom)
        self.loseConnection()

class MigrateClientFactory(ClientFactory):

    def __init__(self, minfo):
        ClientFactory.__init__(self)
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
        self.dst_host = dst
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
        dominfo = xd.domain_get(self.dom)
        if dominfo:
            val = return sxp.to_string(dominfo)
        else:
            val = None
        return None

    def error(self, err):
        self.state = 'error'

    def ok(self, dom):
        self.state = 'ok'
        self.dst_dom = dom

    def close(self):
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
    
    def migrate_begin(self, dom, host):
        # Check dom for existence, not migrating already.
        # Subscribe to migrate notifications (for updating).
        id = self.nextid()
        info = XenMigrateInfo(id, dom, host, XFRD_PORT)
        self._add_migrate(id, info)
        mcf = MigrateClientFactory(info)
        reactor.connectTCP('localhost', XFRD_PORT, mcf)
        return info.deferred

def instance():
    global inst
    try:
        inst
    except:
        inst = XendMigrate()
    return inst
