class Factory:

    def __init__(self):
        pass

    def startedConnecting(self):
        print 'ServerProtocolFactory>startedConnecting>'
        pass

    def doStart(self):
        print 'ServerProtocolFactory>doStart>'
        pass

    def doStop(self):
        print 'ServerProtocolFactory>doStop>'
        pass

    def buildProtocol(self, addr):
        print 'ServerProtocolFactory>buildProtocol>', addr
        return Protocol(self)

class ServerFactory(Factory):
    pass
    
class ClientFactory(Factory):
    pass

class Protocol:

    factory = None
    transport = None
    connected = False

    def __init__(self, factory):
        self.factory = factory

    def setTransport(self, transport):
        self.transport = transport
        self.connected = bool(transport)

    def getTransport(self):
        return self.transport

    def connectionMade(self, addr):
        print 'Protocol>connectionMade>', addr
        pass

    def connectionLost(self, reason=None):
        print 'Protocol>connectionLost>', reason
        pass

    def dataReceived(self, data):
        print 'Protocol>dataReceived>'
        pass

    def write(self, data):
        if self.transport:
            return self.transport.write(data)
        else:
            return 0

    def read(self):
        if self.transport:
            return self.transport.read()
        else:
            return None

class TestClientFactory(Factory):

    def buildProtocol(self, addr):
        print 'TestClientProtocolFactory>buildProtocol>', addr
        return TestClientProtocol(self)
    
class TestClientProtocol(Protocol):

    def connectionMade(self, addr):
        print 'TestProtocol>connectionMade>', addr
        self.write("hello")
        self.write("there")

class TestServerFactory(Factory):

    def buildProtocol(self, addr):
        print 'TestServerProtocolFactory>buildProtocol>', addr
        return TestServerProtocol(self)
    
class TestServerProtocol(Protocol):

    def dataReceived(self, data):
        print 'TestServerProtocol>dataReceived>', len(data), data
        #sys.exit(0)
        import os
        os._exit(0)
        
