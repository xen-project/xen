import sys
import StringIO

from xen.web import reactor, protocol

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend import EventServer; eserver = EventServer.instance()
from xen.xend.XendError import XendError
from xen.xend import XendRoot; xroot = XendRoot.instance()

DEBUG = 0

class EventProtocol(protocol.Protocol):
    """Asynchronous handler for a connected event socket.
    """

    def __init__(self, daemon):
        #protocol.Protocol.__init__(self)
        self.daemon = daemon
        # Event queue.
        self.queue = []
        # Subscribed events.
        self.events = []
        self.parser = sxp.Parser()
        self.pretty = 0

        # For debugging subscribe to everything and make output pretty.
        #self.subscribe(['*'])
        self.pretty = 1

    def dataReceived(self, data):
        try:
            self.parser.input(data)
            if self.parser.ready():
                val = self.parser.get_val()
                res = self.dispatch(val)
                self.send_result(res)
            if self.parser.at_eof():
                self.loseConnection()
        except SystemExit:
            raise
        except:
            self.send_error()

    def loseConnection(self):
        if self.transport:
            self.transport.loseConnection()
        if self.connected:
            reactor.callLater(0, self.connectionLost)

    def connectionLost(self, reason=None):
        self.unsubscribe()

    def send_reply(self, sxpr):
        io = StringIO.StringIO()
        if self.pretty:
            PrettyPrint.prettyprint(sxpr, out=io)
        else:
            sxp.show(sxpr, out=io)
        print >> io
        io.seek(0)
        if self.transport:
            return self.transport.write(io.getvalue())
        else:
            return 0

    def send_result(self, res):
        if res is None:
            resp = ['ok']
        else:
            resp = ['ok', res]
        return self.send_reply(resp)

    def send_error(self):
        (extype, exval) = sys.exc_info()[:2]
        return self.send_reply(['err',
                                ['type', str(extype)],
                                ['value', str(exval)]])

    def send_event(self, val):
        return self.send_reply(['event', val[0], val[1]])

    def unsubscribe(self):
        for event in self.events:
            eserver.unsubscribe(event, self.queue_event)

    def subscribe(self, events):
        self.unsubscribe()
        for event in events:
            eserver.subscribe(event, self.queue_event)
        self.events = events

    def queue_event(self, name, v):
        # Despite the name we don't queue the event here.
        # We send it because the transport will queue it.
        self.send_event([name, v])
        
    def opname(self, name):
         return 'op_' + name.replace('.', '_')

    def operror(self, name, req):
        raise XendError('Invalid operation: ' +name)

    def dispatch(self, req):
        op_name = sxp.name(req)
        op_method_name = self.opname(op_name)
        op_method = getattr(self, op_method_name, self.operror)
        return op_method(op_name, req)

    def op_help(self, name, req):
        def nameop(x):
            if x.startswith('op_'):
                return x[3:].replace('_', '.')
            else:
                return x
        
        l = [ nameop(k) for k in dir(self) if k.startswith('op_') ]
        return l

    def op_quit(self, name, req):
        self.loseConnection()

    def op_exit(self, name, req):
        sys.exit(0)

    def op_pretty(self, name, req):
        self.pretty = 1

    def op_console_disconnect(self, name, req):
        id = sxp.child_value(req, 'id')
        if not id:
            raise XendError('Missing console id')
        id = int(id)
        self.daemon.console_disconnect(id)

    def op_info(self, name, req):
        val = ['info']
        #val += self.daemon.consoles()
        #val += self.daemon.blkifs()
        #val += self.daemon.netifs()
        #val += self.daemon.usbifs()
        return val

    def op_sys_subscribe(self, name, v):
        # (sys.subscribe event*)
        # Subscribe to the events:
        self.subscribe(v[1:])

    def op_sys_inject(self, name, v):
        # (sys.inject event)
        event = v[1]
        eserver.inject(sxp.name(event), event)

    def op_trace(self, name, v):
        mode = (v[1] == 'on')
        self.daemon.tracing(mode)

    def op_log_stderr(self, name, v):
        mode = v[1]
        logging = xroot.get_logging()
        if mode == 'on':
            logging.addLogStderr()
        else:
            logging.removeLogStderr()

    def op_debug_msg(self, name, v):
        mode = v[1]
        import messages
        messages.DEBUG = (mode == 'on')

    def op_debug_controller(self, name, v):
        mode = v[1]
        import controller
        controller.DEBUG = (mode == 'on')

    def op_domain_ls(self, name, v):
        xd = xroot.get_component("xen.xend.XendDomain")
        return xd.domain_ls()

    def op_domain_configure(self, name, v):
        domid = sxp.child_value(v, "dom")
        config = sxp.child_value(v, "config")
        if domid is None:
            raise XendError("missing domain id")
        if config is None:
            raise XendError("missing domain config")
        xd = xroot.get_component("xen.xend.XendDomain")
        xd.domain_configure(domid, config)

    def op_domain_unpause(self, name, v):
        domid = sxp.child_value(v, "dom")
        if domid is None:
            raise XendError("missing domain id")
        xd = xroot.get_component("xen.xend.XendDomain")
        xd.domain_unpause(domid)

class EventFactory(protocol.ServerFactory):
    """Asynchronous handler for the event server socket.
    """

    def __init__(self, daemon):
        #protocol.ServerFactory.__init__(self)
        self.daemon = daemon

    def buildProtocol(self, addr):
        return EventProtocol(self.daemon)

def listenEvent(daemon):
    factory = EventFactory(daemon)
    if xroot.get_xend_unix_server():
        path = '/var/lib/xend/event-socket'
        reactor.listenUNIX(path, factory)
    if xroot.get_xend_http_server():
        port = xroot.get_xend_event_port()
        interface = xroot.get_xend_address()
        reactor.listenTCP(port, factory, interface=interface)
