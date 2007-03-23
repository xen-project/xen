#!/usr/bin/python

"""
 Report.py - Handles the coordination of xm-test xml-reporting modules

 Copyright (C) International Business Machines Corp., 2005
 Author: Dan Smith <danms@us.ibm.com>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; under version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""

import OSReport
import ProgReport
import ResultReport
import utils

import sys
import os
import xml.dom.minidom
import httplib
import urllib
import re
from urlparse import urlparse

class XmTestReport:

    def __init__(self, files):
        self.files = files

    def __getContactInfo(self):
        if os.access("contact_info", os.R_OK):
            c = file("contact_info")
            line = c.readline()
            line = line.strip()
            return line
        else:
            return "nobody@nowhere.com"

    def __stringify(self, fileName):
        f = file(fileName)
        str = f.read()
        f.close()

        return str

    def __str__(self):
        string  = "<testname>xm-test</testname>\n"
        string += "<user>%s</user>\n" % self.__getContactInfo()

        for f in self.files:
            string += self.__stringify(f)

        return string

# Taken from example in Python Cookbook
def encodeForm(fieldList):
    body = []
    boundary = "-------XmTestReportingXML"

    for name in fieldList.keys():
        body.append('--' + boundary)
        body.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (name, "%s.txt" % name))
        body.append('Content-Type: text/plain')
        body.append('')
        body.append(fieldList[name])

    body.append('')
    body.append("--" + boundary + "--")
    body.append('')

    textBody = "\r\n".join(body)

    return 'multipart/form-data; boundary=%s' % boundary, textBody

def postResults(report_server, results):
    if not re.match('http://', report_server):
        report_server = 'http://'+report_server
    (report_host,report_url) = urlparse(report_server)[1:3]
    conn = httplib.HTTPConnection(report_host)

    type, body = encodeForm({"log" : results})

    headers = {"content-type" : type}

    # DEBUG OUTPUT
    # print "BODY\n%s\nBODY\n" % body
    # print "%s\n" % type
    # print headers
    
    conn.request("POST", report_url, body, headers)
    
    resp = conn.getresponse()
    data = resp.read()

    if resp.status == 200:
        print >>sys.stderr, "Your results have been submitted successfully!"
    else:
        print >>sys.stderr, "Unable to submit results:"
        print >>sys.stderr, "[http://%s%s] said %i: %s" % (report_host,
                                                           report_url,
                                                           resp.status,
                                                           resp.reason)
        print >>sys.stderr, data

if __name__ == "__main__":

    if len(sys.argv) <= 1:
        print "Usage: Report.py [opt] <outputfiles...>"
        print "Where:"
        print "-d    : don't submit, just dump XML"
        print "-D    : do submit and dump XML"
        sys.exit(1)

    submit = True
    dump = False
    files = []

    report_server = sys.argv[1]

    for a in sys.argv[2:]:
        if a == "-d":
            submit = False
            dump = True
        elif a == "-D":
            dump = True
            submit = True

        else:
            if not os.access(a, os.R_OK):
                print "Unable to access file: %s" % a
                sys.exit(1)
            else:
                files.append(a)

    report = XmTestReport(files)

    xmlout = "<xml>\n%s</xml>\n" % report

    if dump:
        print xmlout

    if submit:
        postResults(report_server, xmlout)
    
