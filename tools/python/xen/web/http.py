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
#
#============================================================================
# Parts of this library are derived from Twisted:
# Copyright (C) 2001 Matthew W. Lefkowitz
#
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
#============================================================================

from  mimetools import Message
from cStringIO import StringIO
import math
import socket
import time
import cgi

CONTINUE                        = 100
SWITCHING_PROTOCOLS             = 101

OK                              = 200
CREATED                         = 201
ACCEPTED                        = 202
NON_AUTHORITATIVE_INFORMATION   = 203
NO_CONTENT                      = 204
RESET_CONTENT                   = 205
PARTIAL_CONTENT                 = 206
MULTI_STATUS                    = 207

MULTIPLE_CHOICE                 = 300
MOVED_PERMANENTLY               = 301
FOUND                           = 302
SEE_OTHER                       = 303
NOT_MODIFIED                    = 304
USE_PROXY                       = 305
TEMPORARY_REDIRECT              = 307

BAD_REQUEST                     = 400
UNAUTHORIZED                    = 401
PAYMENT_REQUIRED                = 402
FORBIDDEN                       = 403
NOT_FOUND                       = 404
NOT_ALLOWED                     = 405
NOT_ACCEPTABLE                  = 406
PROXY_AUTH_REQUIRED             = 407
REQUEST_TIMEOUT                 = 408
CONFLICT                        = 409
GONE                            = 410
LENGTH_REQUIRED                 = 411
PRECONDITION_FAILED             = 412
REQUEST_ENTITY_TOO_LARGE        = 413
REQUEST_URI_TOO_LONG            = 414
UNSUPPORTED_MEDIA_TYPE          = 415
REQUESTED_RANGE_NOT_SATISFIABLE = 416
EXPECTATION_FAILED              = 417

INTERNAL_SERVER_ERROR           = 500
NOT_IMPLEMENTED                 = 501
BAD_GATEWAY                     = 502
SERVICE_UNAVAILABLE             = 503
GATEWAY_TIMEOUT                 = 504
VERSION_NOT_SUPPORTED           = 505
INSUFFICIENT_STORAGE_SPACE      = 507
NOT_EXTENDED                    = 510

NO_BODY_CODES = [ NO_CONTENT, NOT_MODIFIED ]
    

STATUS = {
    CONTINUE                        : "Continue",
    SWITCHING_PROTOCOLS             : "Switching protocols",
    
    OK                              : "OK",
    CREATED                         : "Created",
    ACCEPTED                        : "Accepted",
    NON_AUTHORITATIVE_INFORMATION   : "Non-authoritative information",
    NO_CONTENT                      : "No content",
    RESET_CONTENT                   : "Reset content",
    PARTIAL_CONTENT                 : "Partial content",
    MULTI_STATUS                    : "Multi-status",
    
    MULTIPLE_CHOICE                 : "Multiple choice",
    MOVED_PERMANENTLY               : "Moved permanently",
    FOUND                           : "Found",
    SEE_OTHER                       : "See other",
    NOT_MODIFIED                    : "Not modified",
    USE_PROXY                       : "Use proxy",
    TEMPORARY_REDIRECT              : "Temporary redirect",
    
    BAD_REQUEST                     : "Bad request",
    UNAUTHORIZED                    : "Unauthorized",
    PAYMENT_REQUIRED                : "Payment required",
    FORBIDDEN                       : "Forbidden",
    NOT_FOUND                       : "Not found",
    NOT_ALLOWED                     : "Not allowed",
    NOT_ACCEPTABLE                  : "Not acceptable",
    PROXY_AUTH_REQUIRED             : "Proxy authentication required",
    REQUEST_TIMEOUT                 : "Request timeout",
    CONFLICT                        : "Conflict",
    GONE                            : "Gone",
    LENGTH_REQUIRED                 : "Length required",
    PRECONDITION_FAILED             : "Precondition failed",
    REQUEST_ENTITY_TOO_LARGE        : "Request entity too large",
    REQUEST_URI_TOO_LONG            : "Request URI too long",
    UNSUPPORTED_MEDIA_TYPE          : "Unsupported media type",
    REQUESTED_RANGE_NOT_SATISFIABLE : "Requested range not satisfiable",
    EXPECTATION_FAILED              : "Expectation failed",
    
    INTERNAL_SERVER_ERROR           : "Internal server error",
    NOT_IMPLEMENTED                 : "Not implemented",
    BAD_GATEWAY                     : "Bad gateway",
    SERVICE_UNAVAILABLE             : "Service unavailable",
    GATEWAY_TIMEOUT                 : "Gateway timeout",
    VERSION_NOT_SUPPORTED           : "HTTP version not supported",
    INSUFFICIENT_STORAGE_SPACE      : "Insufficient storage space",
    NOT_EXTENDED                    : "Not extended",
    }

def getStatus(code):
    return STATUS.get(code, "unknown")

MULTIPART_FORM_DATA = 'multipart/form-data'
URLENCODED = 'application/x-www-form-urlencoded'

parseQueryArgs = cgi.parse_qs

def timegm(year, month, day, hour, minute, second):
    """Convert time tuple in GMT to seconds since epoch, GMT"""
    EPOCH = 1970
    assert year >= EPOCH
    assert 1 <= month <= 12
    days = 365*(year-EPOCH) + calendar.leapdays(EPOCH, year)
    for i in range(1, month):
        days = days + calendar.mdays[i]
    if month > 2 and calendar.isleap(year):
        days = days + 1
    days = days + day - 1
    hours = days*24 + hour
    minutes = hours*60 + minute
    seconds = minutes*60 + second
    return seconds

def stringToDatetime(dateString):
    """Convert an HTTP date string to seconds since epoch."""
    parts = dateString.split(' ')
    day = int(parts[1])
    month = int(monthname.index(parts[2]))
    year = int(parts[3])
    hour, min, sec = map(int, parts[4].split(':'))
    return int(timegm(year, month, day, hour, min, sec))

class HttpRequest:

    http_version = (1, 1)

    http_version_string = ("HTTP/%d.%d" % http_version)

    max_content_length = 10000
    max_headers = 500

    request_line = None
    request_method = None
    request_uri = None
    request_path = None
    request_query = None
    request_version = None
    content_length = 0
    content = None
    etag = None
    close_connection = True
    response_code = 200
    response_status = "OK"
    response_sent = False
    cached = False
    last_modified = None

    forceSSL = False
    
    def __init__(self, host, rin, out):
        self.host = host
        self.rin = rin
        self.out = out
        self.request_args = {}
        self.args = self.request_args
        self.request_headers = {}
        self.request_cookies = {}
        self.response_headers = {}
        self.response_cookies = {}
        self.output = StringIO()
        self.parseRequest()

    def isSecure(self):
        return self.forceSSL

    def getRequestMethod(self):
        return self.request_method

    def trim(self, str, ends):
        for end in ends:
            if str.endswith(end):
                str = str[ : -len(end) ]
                break
        return str

    def requestError(self, code, msg=None):
        self.sendError(code, msg)
        raise ValueError(self.response_status)

    def sendError(self, code, msg=None):
        self.setResponseCode(code, msg=msg)
        self.sendResponse()

    def parseRequestVersion(self, version):
        try:
            if not version.startswith('HTTP/'):
                raise ValueError
            version_string = version.split('/', 1)[1]
            version_codes = version_string.split('.')
            if len(version_codes) != 2:
                raise ValueError
            request_version = (int(version_codes[0]), int(version_codes[1]))
        except (ValueError, IndexError):
            self.requestError(400, "Bad request version (%s)" % `version`)

    def parseRequestLine(self):
        line = self.trim(self.request_line, ['\r\n', '\n'])
        line_fields = line.split()
        n = len(line_fields)
        if n == 3:
            [method, uri, version] = line_fields
        elif n == 2:
            [method, uri] = line_fields
            version = 'HTTP/0.9'
        else:
            self.requestError(BAD_REQUEST,
                              "Bad request (%s)" % `line`)

        request_version = self.parseRequestVersion(version)

        if request_version > (2, 0):
            self.requestError(VERSION_NOT_SUPPORTED,
                              "HTTP version not supported (%s)" % `version`)
        #if request_version >= (1, 1) and self.http_version >= (1, 1):
        #    self.close_connection = False
        #else:
        #    self.close_connection = True

        self.request_method = method
        self.method = method
        self.request_uri = uri
        self.request_version = version

        uri_query = uri.split('?')
        if len(uri_query) == 1:
            self.request_path = uri
        else:
            self.request_path = uri_query[0]
            self.request_query = uri_query[1]
            self.request_args = parseQueryArgs(self.request_query)
            self.args = self.request_args
            

    def parseRequestHeaders(self):
        header_bytes = ""
        header_count = 0
        while True:
            if header_count >= self.max_headers:
                self.requestError(BAD_REQUEST,
                                  "Bad request (too many headers)")
            line = self.rin.readline()
            header_bytes += line
            header_count += 1
            if line == '\r\n' or line == '\n' or line == '':
                break
        header_input = StringIO(header_bytes)
        self.request_headers = Message(header_input)

    def parseRequestCookies(self):
        cookie_hdr = self.getHeader("cookie")
        if not cookie_hdr: return
        for cookie in cookie_hdr.split(';'):
            try:
                cookie = cookie.lstrip()
                (k, v) = cookie.split('=', 1)
                self.request_cookies[k] = v
            except ValueError:
                pass

    def parseRequestArgs(self):
        if ((self.content is None) or
            (self.request_method != "POST")):
            return
        content_type = self.getHeader('content-type')
        if not content_type:
            return
        (encoding, params) = cgi.parse_header(content_type)
        if encoding == URLENCODED:
            xargs = cgi.parse_qs(self.content.getvalue(),
                                 keep_blank_values=True)
        elif encoding == MULTIPART_FORM_DATA:
            xargs = cgi.parse_multipart(self.content, params)
        else:
            xargs = {}
        self.request_args.update(xargs)

    def getCookie(self, k):
        return self.request_cookies[k]

    def readContent(self):
        try:
            self.content_length = int(self.getHeader("Content-Length"))
        except:
            return
        if self.content_length > self.max_content_length:
            self.requestError(REQUEST_ENTITY_TOO_LARGE)
        self.content = self.rin.read(self.content_length)
        self.content = StringIO(self.content)
        self.content.seek(0,0)

    def parseRequest(self):
        self.request_line = self.rin.readline()
        self.parseRequestLine()
        self.parseRequestHeaders()
        self.parseRequestCookies()
        connection_mode = self.getHeader('Connection')
        self.setCloseConnection(connection_mode)
        self.readContent()
        self.parseRequestArgs()

    def setCloseConnection(self, mode):
        if not mode: return
        mode = mode.lower()
        if mode == 'close':
            self.close_connection = True
        elif (mode == 'keep-alive') and (self.http_version >= (1, 1)):
            self.close_connection = False
        
    def getCloseConnection(self):
        return self.close_connection

    def getHeader(self, k, v=None):
        return self.request_headers.get(k, v)

    def getRequestMethod(self):
        return self.request_method

    def getRequestPath(self):
        return self.request_path

    def setResponseCode(self, code, status=None, msg=None):
        self.response_code = code
        if not status:
            status = getStatus(code)
        self.response_status = status

    def setResponseHeader(self, k, v):
        k = k.lower()
        self.response_headers[k] = v
        if k == 'connection':
            self.setCloseConnection(v)

    setHeader = setResponseHeader

    def setLastModified(self, when):
        # time.time() may be a float, but the HTTP-date strings are
        # only good for whole seconds.
        when = long(math.ceil(when))
        if (not self.last_modified) or (self.last_modified < when):
            self.lastModified = when

        modified_since = self.getHeader('if-modified-since')
        if modified_since:
            modified_since = stringToDatetime(modified_since)
            if modified_since >= when:
                self.setResponseCode(NOT_MODIFIED)
                self.cached = True

    def setContentType(self, ty):
        self.setResponseHeader("Content-Type", ty)

    def setEtag(self, etag):
        if etag:
            self.etag = etag

        tags = self.getHeader("if-none-match")
        if tags:
            tags = tags.split()
            if (etag in tags) or ('*' in tags):
                if self.request_method in ("HEAD", "GET"):
                    code = NOT_MODIFIED
                else:
                    code = PRECONDITION_FAILED
                self.setResponseCode(code)
                self.cached = True

    def addCookie(self, k, v, expires=None, domain=None, path=None,
                  max_age=None, comment=None, secure=None):
        cookie = v
        if expires != None:
            cookie += "; Expires=%s" % expires
        if domain != None:
            cookie += "; Domain=%s" % domain
        if path != None:
            cookie += "; Path=%s" % path
        if max_age != None:
            cookie += "; Max-Age=%s" % max_age
        if comment != None:
            cookie += "; Comment=%s" % comment
        if secure:
            cookie += "; Secure"
        self.response_cookies[k] = cookie

    def sendResponseHeaders(self):
        if self.etag:
            self.setResponseHeader("ETag", self.etag)
        for (k, v) in self.response_headers.items():
            self.send("%s: %s\r\n" % (k.capitalize(), v))
        for (k, v) in self.response_cookies.items():
            self.send("Set-Cookie: %s=%s\r\n" % (k, v))
        self.send("\r\n")
        
    def sendResponse(self):
        if self.response_sent:
            return
        self.response_sent = True
        send_body = self.hasBody()
        if not self.close_connection:
            self.setResponseHeader("Connection", "keep-alive")
        self.setResponseHeader("Pragma", "no-cache")
        self.setResponseHeader("Cache-Control", "no-cache")
        self.setResponseHeader("Expires", "-1")
        if send_body:
            self.output.seek(0, 0)
            body = self.output.getvalue()
            body_length = len(body)
            self.setResponseHeader("Content-Length", body_length)
        if self.http_version > (0, 9):
            self.send("%s %d %s\r\n" % (self.http_version_string,
                                         self.response_code,
                                         self.response_status))
            self.sendResponseHeaders()
        if send_body:
            self.send(body)
        self.flush()

    def write(self, data):
        self.output.write(data)

    def send(self, data):
        #print 'send>', data
        self.out.write(data)

    def flush(self):
        self.out.flush()

    def hasNoBody(self):
        return ((self.request_method == "HEAD") or
                (self.response_code in NO_BODY_CODES) or
                self.cached)

    def hasBody(self):
        return not self.hasNoBody()

    def process(self):
        pass
        return self.close_connection

    def getRequestHostname(self):
        """Get the hostname that the user passed in to the request.

        Uses the 'Host:' header if it is available, and the
        host we are listening on otherwise.
        """
        return (self.getHeader('host') or
                socket.gethostbyaddr(self.getHostAddr())[0]
                ).split(':')[0]

    def getHost(self):
        return self.host

    def getHostAddr(self):
        return self.host[0]
    
    def getPort(self):
        return self.host[1]

    def setHost(self, host, port, ssl=0):
        """Change the host and port the request thinks it's using.

        This method is useful for working with reverse HTTP proxies (e.g.
        both Squid and Apache's mod_proxy can do this), when the address
        the HTTP client is using is different than the one we're listening on.

        For example, Apache may be listening on https://www.example.com, and then
        forwarding requests to http://localhost:8080, but we don't want HTML produced
        to say 'http://localhost:8080', they should say 'https://www.example.com',
        so we do::

           request.setHost('www.example.com', 443, ssl=1)

        """
        self.forceSSL = ssl
        self.received_headers["host"] = host
        self.host = (host, port)

        

