# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Simple publish/subscribe event server.

"""
import string
from threading import Lock

#from twisted.internet import reactor
from xen.web import reactor

# subscribe a.b.c h: map a.b.c -> h
# subscribe a.b.* h: map a.b.* -> h
# subscribe a.b.? h: map a.b.? -> h
#
# for event a.b.c.d:
#
# lookup a.b.c.d, call handlers
#
# lookup a.b.c.?, call handlers
#
# lookup a.b.c.d.*, call handlers
# lookup a.b.c.*, call handlers
# lookup a.b.*, call handlers
# lookup a.*, call handlers
# lookup *, call handlers

# a.b.c.d = (a b c d)
# a.b.c.? = (a b c _)
# a.b.c.* = (a b c . _)

class EventServer:

    DOT = '.'
    QUERY = '?'
    DOT_QUERY = DOT + QUERY
    STAR = '*'
    DOT_STAR = DOT + STAR

    def __init__(self, run=0):
        self.handlers = {}
        self.run = run
        self.queue = []
        self.lock = Lock()

    def start(self):
        """Enable event handling. Sends any queued events.
        """
        try:
            self.lock.acquire()
            self.run = 1
            queue = self.queue
            self.queue = []
        finally:
            self.lock.release()
        for (e,v) in queue:
            self.inject(e, v)

    def stop(self):
        """Suspend event handling. Events injected while suspended
        are queued until we are started again.
        """
        try:
            self.lock.acquire()
            self.run = 0
        finally:
            self.lock.release()

    def subscribe(self, event, handler):
        """Subscribe to an event. For example 'a.b.c.d'.
        A subcription like 'a.b.c.?' ending in '?' matches any value
        for the '?'. A subscription like 'a.b.c.*' ending in '*' matches
        any event type with the same prefix, 'a.b.c' in this case.

        event	event name
        handler event handler fn(event, val)
        """
        try:
            self.lock.acquire()
            hl = self.handlers.get(event)
            if hl is None:
                self.handlers[event] = [handler]
            else:
                hl.append(handler)
        finally:
            self.lock.release()

    def unsubscribe_all(self, event=None):
        """Unsubscribe all handlers for a given event, or all handlers.

        event	event (optional)
        """
        try:
            self.lock.acquire()
            if event == None:
                self.handlers.clear()
            elif event in self.handlers:
                del self.handlers[event]
        finally:
            self.lock.release()
        
    def unsubscribe(self, event, handler):
        """Unsubscribe a given event and handler.

        event	event
        handler handler
        """
        try:
            self.lock.acquire()
            hl = self.handlers.get(event)
            if hl is None:
                return
            if handler in hl:
                hl.remove(handler)
        finally:
            self.lock.release()

    def inject(self, event, val, async=1):
        """Inject an event. Handlers for it are called if running, otherwise
        it is queued.

        event	event type
        val	event value
        """
        try:
            self.lock.acquire()
            if not self.run:
                self.queue.append( (event, val) )
                return
        finally:
            self.lock.release()
            
        if async:
            reactor.callLater(0, self.call_handlers, event, val)
        else:
            self.notify_handlers(event, val)

    def call_handlers(self, event, val):
        """Internal method to call event handlers.
        """
        #print ">event", event, val
        self.call_event_handlers(event, event, val)
        self.call_query_handlers(event, val)
        self.call_star_handlers(event, val)

    def call_event_handlers(self, key, event, val):
        """Call the handlers for an event.
        It is safe for handlers to subscribe or unsubscribe.

        key	key for handler list
        event	event type
        val	event value
        """
        try:
            self.lock.acquire()
            hl = self.handlers.get(key)
            if hl is None:
                return
            # Copy the handler list so that handlers can call
            # subscribe/unsubscribe safely - python list iteration
            # is not safe against list modification.
            hl = hl[:]
        finally:
            self.lock.release()
        # Must not hold the lock while calling the handlers.
        for h in hl:
            try:
                h(event, val)
            except:
                pass
        
    def call_query_handlers(self, event, val):
        """Call regex handlers for events matching 'event' that end in '?'.

        event	event type
        val	event value
        """
        dot_idx = event.rfind(self.DOT)
        if dot_idx == -1:
            self.call_event_handlers(self.QUERY, event, val)
        else:
            event_query = event[0:dot_idx] + self.DOT_QUERY
            self.call_event_handlers(event_query, event, val)

    def call_star_handlers(self, event, val):
        """Call regex handlers for events matching 'event' that end in '*'.

        event	event type
        val	event value
        """
        etype = string.split(event, self.DOT)
        for i in range(len(etype), 0, -1):
            event_star = self.DOT.join(etype[0:i]) + self.DOT_STAR
            self.call_event_handlers(event_star, event, val)
        self.call_event_handlers(self.STAR, event, val)       

def instance():
    global inst
    try:
        inst
    except:
        inst = EventServer()
        inst.start()
    return inst

def main():
    def sys_star(event, val):
        print 'sys_star', event, val

    def sys_foo(event, val):
        print 'sys_foo', event, val
        s.unsubscribe('sys.foo', sys_foo)

    def sys_foo2(event, val):
        print 'sys_foo2', event, val

    def sys_bar(event, val):
        print 'sys_bar', event, val

    def sys_foo_bar(event, val):
        print 'sys_foo_bar', event, val

    def foo_bar(event, val):
        print 'foo_bar', event, val

    s = EventServer()
    s.start()
    s.subscribe('sys.*', sys_star)
    s.subscribe('sys.foo', sys_foo)
    s.subscribe('sys.foo', sys_foo2)
    s.subscribe('sys.bar', sys_bar)
    s.subscribe('sys.foo.bar', sys_foo_bar)
    s.subscribe('foo.bar', foo_bar)
    s.inject('sys.foo', 'hello')
    print
    s.inject('sys.bar', 'hello again')
    print
    s.inject('sys.foo.bar', 'hello again')
    print
    s.inject('foo.bar', 'hello again')
    print
    s.inject('foo', 'hello again')
    print
    s.start()
    s.unsubscribe('sys.*', sys_star)
    s.unsubscribe_all('sys.*')
    s.inject('sys.foo', 'hello')

if __name__ == "__main__":
    main()

