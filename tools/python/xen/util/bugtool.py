#!/usr/bin/env python

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
# Copyright (c) 2005, XenSource Ltd.


import errno
import getpass
import httplib
import re
import os
import os.path
import StringIO
import sys
import tarfile
import tempfile
import time
import urllib

import xen.lowlevel.xc

from xen.xend import encode


SERVER = 'bugzilla.xensource.com'
SHOW_BUG_PATTERN = 'http://%s/bugzilla/show_bug.cgi?id=%%d' % SERVER
ATTACH_PATTERN = \
 'http://%s/bugzilla/attachment.cgi?bugid=%%d&action=enter' % SERVER

TITLE_RE = re.compile(r'<title>(.*)</title>')

FILES_TO_SEND = [ '/var/log/' + x for x in 
                  [ 'syslog', 'messages', 'debug',
                    'xen/xend-debug.log', 'xen/xenstored-trace.log',
                    'xen/xen-hotplug.log', 'xen/xend.log' ] +
                  [ 'xen/xend.log.%d' % z for z in range(1,6) ] ]
#FILES_TO_SEND = [  ]


def main(argv = None):
    if argv is None:
        argv = sys.argv

    print '''
This application will collate the Xen dmesg output, details of the hardware
configuration of your machine, information about the build of Xen that you are
using, plus, if you allow it, various logs.

The information collated can either be posted to a Xen Bugzilla bug (this bug
must already exist in the system, and you must be a registered user there), or
it can be saved as a .tar.bz2 for sending or archiving.

The collated logs may contain private information, and if you are at all
worried about that, you should exit now, or you should explicitly exclude
those logs from the archive.

'''
    
    bugball = []

    xc = xen.lowlevel.xc.xc()

    def do(n, f):
        try:
            s = f()
        except Exception, exn:
            s = str(exn)
        bugball.append(string_iterator(n, s))

    do('xen-dmesg', lambda: xc.readconsolering())
    do('physinfo',  lambda: prettyDict(xc.physinfo()))
    do('xeninfo',   lambda: prettyDict(xc.xeninfo()))

    for filename in FILES_TO_SEND:
        if not os.path.exists(filename):
            continue

        if yes('Include %s? [Y/n] ' % filename):
            bugball.append(file(filename))

    maybeAttach(bugball)

    if (yes('''
Do you wish to save these details as a tarball (.tar.bz2)? [Y/n] ''')):
        tar(bugball)

    return 0


def maybeAttach(bugball):
    if not yes('''
Do you wish to attach these details to a Bugzilla bug? [Y/n] '''):
        return

    bug = int(raw_input('Bug number? '))

    bug_title = getBugTitle(bug)

    if bug_title == 'Search by bug number' or bug_title == 'Invalid Bug ID':
        print >>sys.stderr, 'Bug %d does not exist!' % bug
        maybeAttach(bugball)
    elif yes('Are you sure that you want to attach to %s? [Y/n] ' %
             bug_title):
        attach(bug, bugball)
    else:
        maybeAttach(bugball)


def attach(bug, bugball):
    username = raw_input('Bugzilla username: ')
    password = getpass.getpass('Bugzilla password: ')

    conn = httplib.HTTPConnection(SERVER)
    try:
        for f in bugball:
            send(bug, conn, f, f.name, username, password)
    finally:
        conn.close()


def getBugTitle(bug):
    f = urllib.urlopen(SHOW_BUG_PATTERN % bug)

    try:
        for line in f:
            m = TITLE_RE.search(line)
            if m:
                return m.group(1)
    finally:
        f.close()

    raise ValueError("Could not find title of bug %d!" % bug)


def send(bug, conn, fd, filename, username, password):

    print "Attaching %s to bug %d." % (filename, bug)
    
    headers, data = encode.encode_data(
        { 'bugid'                : str(bug),
          'action'               : 'insert',
          'data'                 : fd,
          'description'          : '%s from %s' % (filename, username),
          'contenttypeselection' : 'text/plain',
          'contenttypemethod'    : 'list',
          'ispatch'              : '0',
          'GoAheadAndLogIn'      : '1',
          'Bugzilla_login'       : username,
          'Bugzilla_password'    : password,
          })
    
    conn.request('POST',ATTACH_PATTERN % bug, data, headers)
    response = conn.getresponse()
    try:
        body = response.read()
        m = TITLE_RE.search(body)

        if response.status != 200:
            print >>sys.stderr, (
                'Attach failed: %s %s.' % (response.status, response.reason))
        elif not m or m.group(1) != 'Changes Submitted':
            print >>sys.stderr, (
                'Attach failed: got a page titled %s.' % m.group(1))
        else:
            print "Attaching %s to bug %d succeeded." % (filename, bug)
    finally:
        response.close()


def tar(bugball):
    filename = raw_input('Tarball destination filename? ')

    now = time.time()

    tf = tarfile.open(filename, 'w:bz2')

    try:
        for f in bugball:
            ti = tarfile.TarInfo(f.name.split('/')[-1])
            if hasattr(f, 'size'):
                ti.size = f.size()
            else:
                ti.size = os.stat(f.name).st_size

            ti.mtime = now
            ti.type = tarfile.REGTYPE
            ti.uid = 0
            ti.gid = 0
            ti.uname = 'root'
            ti.gname = 'root'

            f.seek(0) # If we've added this file to a bug, it will have been
                      # read once already, so reset it.
            tf.addfile(ti, f)
    finally:
        tf.close()

    print 'Writing tarball %s successful.' % filename


def prettyDict(d):
    format = '%%-%ds: %%s' % max(map(len, [k for k, _ in d.items()]))
    return '\n'.join([format % i for i in d.items()]) + '\n'


class string_iterator(StringIO.StringIO):
    def __init__(self, name, val):
        StringIO.StringIO.__init__(self, val)
        self.name = name

    def size(self):
        return len(self.getvalue())


def yes(prompt):
    yn = raw_input(prompt)

    return len(yn) == 0 or yn.lower()[0] == 'y'


if __name__ == "__main__":
    sys.exit(main())
