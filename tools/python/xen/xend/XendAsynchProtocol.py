# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from twisted.protocols import http
from twisted.internet.protocol import ClientCreator
from twisted.internet.defer import Deferred
from twisted.internet import reactor

from XendProtocol import XendClientProtocol, XendRequest

class AsynchXendClient(http.HTTPClient):
    """A subclass of twisted's HTTPClient to deal with a connection to xend.
    Makes the request when connected, and delegates handling responses etc.
    to its protocol (usually an AsynchXendClientProtocol instance).
    """
    def __init__(self, protocol, request):
        self.protocol = protocol
        self.request = request

    def connectionMade(self):
        request = self.request
        url = self.request.url
        self.sendCommand(request.method, url.fullpath())
        self.sendHeader('Host', url.location())
        for (k, v) in request.headers.items():
            self.sendHeader(k, v)
        if request.data:
            self.sendHeader('Content-Length', len(request.data))
        self.endHeaders()
        if request.data:
            self.transport.write(request.data)

    def handleStatus(self, version, status, message):
        return self.protocol.handleStatus(version, status, message)

    def handleHeader(self, key, val):
        return self.protocol.handleHeader(key, val)

    def handleResponse(self, data):
        return self.protocol.handleResponse(data)

class AsynchXendClientProtocol(XendClientProtocol):
    """An asynchronous xend client. Uses twisted to connect to xend
    and make the request. It does not block waiting for the result,
    but sets up a deferred that is called when the result becomes available.

    Uses AsynchXendClient to manage the connection.
    """
    def __init__(self):
        self.err = None
        self.headers = {}

    def xendRequest(self, url, method, args=None):
        """Make a request to xend. The returned deferred is called when
        the result is available.
        
        @param url:    xend request url
        @param method: http method: POST or GET
        @param args:   request arguments (dict)
        @return: deferred
        """
        request = XendRequest(url, method, args)
        self.deferred = Deferred()
        clientCreator = ClientCreator(reactor, AsynchXendClient, self, request)
        clientCreator.connectTCP(url.host, url.port)
        return self.deferred

    def callErrback(self, err):
        if not self.deferred.called:
            self.err = err
            self.deferred.errback(err)
        return err

    def callCallback(self, val):
        if not self.deferred.called:
            self.deferred.callback(val)
        return val

    def handleException(self, err):
        return self.callErrback(err)

    def handleHeader(self, key, val):
        self.headers[key.lower()] = val

    def getHeader(self, key):
        return self.headers.get(key.lower())

    def handleResponse(self, data):
        if self.err: return self.err
        val = XendClientProtocol.handleResponse(self, data)
        if isinstance(val, Exception):
            self.callErrback(val)
        else:
            self.callCallback(val)
        return val
