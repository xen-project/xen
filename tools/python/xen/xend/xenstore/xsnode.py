#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
#============================================================================
import errno
import os
import os.path
import select
import socket
import sys
import threading
import time

from xen.lowlevel import xs
from xen.xend import sxp
from xen.xend.PrettyPrint import prettyprint

SELECT_TIMEOUT = 2.0

def getEventPath(event):
    if event and event.startswith("/"):
        event = event[1:]
    return os.path.join("/event", event)

def getEventIdPath(event):
    return os.path.join(getEventPath(event), "@eid")

class Subscription:

    def __init__(self, path, fn, sid):
        self.path = path
        self.watcher = None
        self.fn = fn
        self.sid = sid

    def getPath(self):
        return self.path

    def getSid(self):
        return self.sid

    def watch(self, watcher):
        self.watcher = watcher
        watcher.addSubs(self)

    def unwatch(self):
        watcher = self.watcher
        if watcher:
            self.watcher = None
            watcher.delSubs(self)
        return watcher

    def notify(self, token, path, val):
        try:
            self.fn(self, token, path, val)
        except SystemExit:
            raise
        except Exception, ex:
            pass

class Watcher:

    def __init__(self, store, path):
        self.path = path
        store.mkdirs(self.path)
        self.xs = None
        self.subscriptions = []

    def fileno(self):
        if self.xs:
            return self.xs.fileno()
        else:
            return -1

    def getPath(self):
        return self.path

    def getToken(self):
        return self.path

    def addSubs(self, subs):
        self.subscriptions.append(subs)
        self.watch()

    def delSubs(self, subs):
        self.subscriptions.remove(subs)
        if len(self.subscriptions) == 0:
            self.unwatch()

    def watch(self):
        if self.xs: return
        self.xs = xs.open()
        self.xs.watch(path=self.getPath(), token=self.getToken())

    def unwatch(self):
        if self.xs:
## Possibly crashes xenstored.
##            try:
##                self.xs.unwatch(path=self.getPath(), token=self.getToken())
##            except Exception, ex:
##                print 'Watcher>unwatch>', ex
            try:
                self.xs.close()
            except Exception, ex:
                pass
            self.xs = None
            
    def watching(self):
        return self.xs is not None

    def getNotification(self):
        p = self.xs.read_watch()
        self.xs.acknowledge_watch(p[1])
        return p

    def notify(self):
        try:
            (path, token) = self.getNotification()
            if path.endswith("@eid"):
                pass
            else:
                val = self.xs.read(path)
                for subs in self.subscriptions:
                    subs.notify(token, path, val)
        except SystemExit:
            raise
        except Exception, ex:
            raise

class EventWatcher(Watcher):

    def __init__(self, store, path, event):
        Watcher.__init__(self, store, path)
        self.event = event
        self.eidPath = getEventIdPath(event)
        if not store.exists(self.eidPath):
            store.write(self.eidPath, str(0))

    def getEvent(self):
        return self.event

    def getToken(self):
        return self.event

class XenStore:

    xs = None
    watchThread = None
    subscription_id = 1
    
    def __init__(self):
        self.subscriptions = {}
        self.watchers = {}
        self.write("/", "")

    def getxs(self):
        if self.xs is None:
            ex = None
            for i in range(0,20):
                try:
                    self.xs = xs.open()
                    ex = None
                    break
                except SystemExit:
                    raise
                except Exception, ex:
                    print >>sys.stderr, "Exception connecting to xenstored:", ex
                    print >>sys.stderr, "Trying again..."
                    time.sleep(1)
            else:
                raise ex
            
        #todo would like to reconnect if xs conn closes (e.g. daemon restart).
        return self.xs

    def dump(self, path="/", out=sys.stdout):
        print 'dump>', path
        val = ['node']
        val.append(['path',  path])
##         perms = ['perms']
##         for p in self.getPerms(path):
##             l = ['perm']
##             l.append('dom', p.get['dom'])
##             for k in ['read', 'write', 'create', 'owner']:
##                 v = p.get(k)
##                 l.append([k, v])
##             perms.append(l)
##         val.append(perms)
        data = self.read(path)
        if data:
            val.append(['data',  data])
        children = ['children']
        for x in self.lsPaths(path):
            print 'dump>', 'child=', x
            children.append(self.dump(x))
        if len(children) > 1:
            val.append(children)
        prettyprint(val, out=out)
        return val

    def getPerms(self, path):
        return self.getxs().get_permissions(path)

    def ls(self, path="/"):
        return self.getxs().ls(path)

    def lsPaths(self, path="/"):
        return [ os.path.join(path, x) for x in self.ls(path) ]

    def lsr(self, path="/", list=None):
        if list is None:
            list = []
        list.append(path)
        for x in self.lsPaths(path):
            list.append(x)
            self.lsr(x, list=list)
        return list

    def rm(self, path):
        try:
            #for x in self.lsPaths():
            #    self.getxs().rm(x)
            self.getxs().rm(path)
        except:
            pass

    def exists(self, path):
        try:
            self.getxs().ls(path)
            return True
        except RuntimeError, ex:
            if ex.args[0] == errno.ENOENT:
                return False
            else:
                raise

    def mkdirs(self, path):
        if self.exists(path):
            return
        elts = path.split("/")
        p = "/"
        for x in elts:
            if x == "": continue
            p = os.path.join(p, x)
            if not self.exists(p):
                self.getxs().write(p, "", create=True)

    def read(self, path):
        try:
            return self.getxs().read(path)
        except RuntimeError, ex:
            if ex.args[0] == errno.EISDIR:
                return None
            else:
                raise

    def create(self, path, excl=False):
        self.write(path, "", create=True, excl=excl)

    def write(self, path, data, create=True, excl=False):
        self.mkdirs(path)
        try:
            self.getxs().write(path, data, create=create, excl=excl)
        except Exception, ex:
            raise

    def begin(self, path):
        self.getxs().transaction_start(path)

    def commit(self, abandon=False):
        self.getxs().transaction_end(abort=abandon)

    def watch(self, path, fn):
        watcher = self.watchers.get(path)
        if not watcher:
            watcher = self.addWatcher(Watcher(self, path))
        return self.addSubscription(watcher, fn)
        
    def unwatch(self, sid):
        s = self.subscriptions.get(sid)
        if not s: return
        del self.subscriptions[s.sid]
        watcher = s.unwatch()
        if watcher and not watcher.watching():
            try:
                del self.watchers[watcher.getPath()]
            except:
                pass

    def subscribe(self, event, fn):
        path = getEventPath(event)
        watcher = self.watchers.get(path)
        if not watcher:
            watcher = self.addWatcher(EventWatcher(self, path, event))
        return self.addSubscription(watcher, fn)

    unsubscribe = unwatch

    def sendEvent(self, event, data):
        eventPath = getEventPath(event)
        eidPath = getEventIdPath(event)
        try:
            #self.begin(eventPath)
            self.mkdirs(eventPath)
            eid = 1
            if self.exists(eidPath):
                try:
                    eid = int(self.read(eidPath))
                    eid += 1
                except Exception, ex:
                    pass
            self.write(eidPath, str(eid))
            self.write(os.path.join(eventPath, str(eid)), data)
        finally:
            #self.commit()
            pass

    def addWatcher(self, watcher):
        self.watchers[watcher.getPath()] = watcher
        self.watchStart()
        return watcher

    def addSubscription(self, watcher, fn):
        self.subscription_id += 1
        subs = Subscription(watcher.getPath(), fn, self.subscription_id)
        self.subscriptions[subs.sid] = subs
        subs.watch(watcher)
        return subs.sid

    def watchStart(self):
        if self.watchThread: return
        self.watchThread = threading.Thread(name="Watcher",
                                            target=self.watchMain)
        self.watchThread.setDaemon(True)
        self.watchThread.start()
        
    def watchMain(self):
        try:
            while True:
                if self.watchThread is None: return
                if not self.watchers:
                    return
                rd = self.watchers.values()
                try:
                    (srd, swr, ser) = select.select(rd, [], [], SELECT_TIMEOUT)
                    for watcher in srd:
                        watcher.notify()
                except socket.error, ex:
                    if ex.args[0] in (EAGAIN, EINTR):
                        pass
                    else:
                        raise
        finally:
            self.watchThread = None

    def introduceDomain(self, dom, page, evtchn, path):
        try:
            self.getxs().introduce_domain(dom, page, evtchn.port1, path)
        except RuntimeError, ex:
            if ex.args[0] == errno.EISCONN:
                return None
            else:
                raise

    def releaseDomain(self, dom):
        self.getxs().release_domain(dom)

def getXenStore():
    global xenstore
    try:
        return xenstore
    except:
        xenstore = XenStore()
        return xenstore

def sendEvent(event, val):
    getXenStore.sendEvent(event, val)

def subscribe(event, fn):
    return getXenStore().subscribe(event, fn)

def unsubscribe(sid):
    getXenStore().unsubscribe(sid)

class XenNode:

    def __init__(self, path="/", create=True):
        self.store = getXenStore()
        self.path = path
        if not self.store.exists(path):
            if create:
                self.store.create(path)
            else:
                raise ValueError("path does not exist: '%s'" % path)

    def getStore(self):
        return self.store

    def relPath(self, path=""):
        if not path:
            return self.path
        if path and path.startswith("/"):
            path = path[1:]
        return os.path.join(self.path, path)

    def delete(self, path=""):
        self.store.rm(self.relPath(path))

    def exists(self, path=""):
        return self.store.exists(self.relPath(path))

    def getNode(self, path="", create=True):
        if path == "":
            return self
        else:
            return XenNode(self.relPath(path=path), create=create)

    getChild = getNode

    def getData(self, path=""):
        path = self.relPath(path)
        try:
            return self.store.read(path)
        except:
            return None

    def setData(self, data, path=""):
        return self.store.write(self.relPath(path), data)

    def getLock(self):
        return None

    def lock(self, lockid):
        return None

    def unlock(self, lockid):
        return None

    def deleteChild(self, name):
        self.delete(name)

    def deleteChildren(self):
        for name in self.ls():
            self.deleteChild(name)

    def getChildren(self):
        return [ self.getNode(name) for name in self.ls() ]

    def ls(self):
        return self.store.ls(self.path)

    def introduceDomain(self, dom, page, evtchn, path):
        self.store.introduceDomain(dom, page, evtchn, path)
        
    def releaseDomain(self, dom):
        self.store.releaseDomain(dom)

    def watch(self, fn, path=""):
        """Watch a path for changes. The path is relative
        to the node and defaults to the node itself.
        """
        return self.store.watch(self.relPath(path), fn)

    def unwatch(self, sid):
        return self.store.unwatch(sid)

    def subscribe(self, event, fn):
        return self.store.subscribe(event, fn)

    def unsubscribe(self, sid):
        self.store.unsubscribe(sid)

    def sendEvent(self, event, data):
        return self.store.sendEvent(event, data)

    def __repr__(self):
        return "<XenNode %s>" % self.path


