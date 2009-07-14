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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
#============================================================================

"""Encoding for arguments to HTTP calls.
   Uses the url-encoding with MIME type 'application/x-www-form-urlencoded'
   if the data does not include files. Otherwise it uses the encoding with
   MIME type 'multipart/form-data'. See the HTML4 spec for details.

   """
import sys
import types
from StringIO import StringIO

import urllib
import random
import md5

# Extract from HTML4 spec.
## The following example illustrates "multipart/form-data"
## encoding. Suppose we have the following form:

##  <FORM action="http://server.com/cgi/handle"
##        enctype="multipart/form-data"
##        method="post">
##    <P>
##    What is your name? <INPUT type="text" name="submit-name"><BR>
##    What files are you sending? <INPUT type="file" name="files"><BR>
##    <INPUT type="submit" value="Send"> <INPUT type="reset">
##  </FORM>

## If the user enters "Larry" in the text input, and selects the text
## file "file1.txt", the user agent might send back the following data:

##    Content-Type: multipart/form-data; boundary=AaB03x

##    --AaB03x
##    Content-Disposition: form-data; name="submit-name"

##    Larry
##    --AaB03x
##    Content-Disposition: form-data; name="files"; filename="file1.txt"
##    Content-Type: text/plain

##    ... contents of file1.txt ...
##    --AaB03x--

## If the user selected a second (image) file "file2.gif", the user agent
## might construct the parts as follows:

##    Content-Type: multipart/form-data; boundary=AaB03x

##    --AaB03x
##    Content-Disposition: form-data; name="submit-name"

##    Larry
##    --AaB03x
##    Content-Disposition: form-data; name="files"
##    Content-Type: multipart/mixed; boundary=BbC04y

##    --BbC04y
##    Content-Disposition: file; filename="file1.txt"
##    Content-Type: text/plain

##    ... contents of file1.txt ...
##    --BbC04y
##    Content-Disposition: file; filename="file2.gif"
##    Content-Type: image/gif
##    Content-Transfer-Encoding: binary

##    ...contents of file2.gif...
##    --BbC04y--
##    --AaB03x--

__all__ = ['encode_data', 'encode_multipart', 'encode_form', 'mime_boundary' ]

def data_values(d):
    if isinstance(d, types.DictType):
        return d.items()
    else:
        return d

def encode_data(d):
    """Encode some data for HTTP transport.
    The encoding used is stored in 'Content-Type' in the headers.

    d data - sequence of tuples or dictionary
    returns a 2-tuple of the headers and the encoded data
    """
    val = ({}, None)
    if d is None: return val
    multipart = 0
    for (_, v) in data_values(d):
        if encode_isfile(v):
            multipart = 1
            break
    if multipart:
        val = encode_multipart(d)
    else:
        val = encode_form(d)
    return val

def encode_isfile(v):
    if isinstance(v, types.FileType):
        return 1
    if hasattr(v, 'readlines'):
        return 1
    return 0

def encode_multipart(d):
    boundary = mime_boundary()
    hdr = { 'Content-Type': 'multipart/form-data; boundary=' + boundary }
    out = StringIO()
    for (k,v) in data_values(d):
        out.write('--')
        out.write(boundary)
        out.write('\r\n')
        if encode_isfile(v):
            out.write('Content-Disposition: form-data; name="')
            out.write(k)
            if hasattr(v, 'name'):
                out.write('"; filename="')
                out.write(v.name)
            out.write('"\r\n')
            out.write('Content-Type: application/octet-stream\r\n')
            out.write('\r\n')
            for l in v.readlines():
               out.write(l)  
        else:
            out.write('Content-Disposition: form-data; name="')
            out.write(k)
            out.write('"\r\n')
            out.write('\r\n')
            out.write(str(v))
            out.write('\r\n')
    out.write('--')
    out.write(boundary)
    out.write('--')
    out.write('\r\n')
    return (hdr, out.getvalue())

def mime_boundary():
    random.seed()
    m = md5.new()
    for _ in range(0, 10):
        c = chr(random.randint(1, 255))
        m.update(c)
    b = m.hexdigest()
    return b[0:16]

def encode_form(d):
    hdr = { 'Content-Type': 'application/x-www-form-urlencoded' }
    val = urllib.urlencode(d)
    return (hdr, val)

def main():
    #d = {'a': 1, 'b': 'x y', 'c': file('conf.sxp') }
    #d = {'a': 1, 'b': 'x y' }
    d = [ ('a', 1), ('b', 'x y'), ('c', file('conf.sxp')) ]
    #d = [ ('a', 1), ('b', 'x y')]
    v = encode_data(d)
    print v[0]
    sys.stdout.write(v[1])
    print

if __name__ == "__main__":
    main()
