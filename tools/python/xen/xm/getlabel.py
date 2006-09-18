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
# Copyright (C) 2006 International Business Machines Corp.
# Author: Bryan D. Payne <bdpayne@us.ibm.com>
#============================================================================

"""Show the label for a domain or resoruce.
"""
import sys, os, re
from xen.util import dictio
from xen.util import security

def usage():
    print "\nUsage: xm getlabel dom <configfile>"
    print "       xm getlabel res <resource>\n"
    print "  This program shows the label for a domain or resource.\n"
    security.err("Usage")


def get_resource_label(resource):
    """Gets the resource label
    """
    # read in the resource file
    file = security.res_label_filename
    try:
        access_control = dictio.dict_read("resources", file)
    except:
        security.err("Resource label file not found")

    # get the entry and print label
    if access_control.has_key(resource):
        policy = access_control[resource][0]
        label = access_control[resource][1]
        print "policy="+policy+",label="+label
    else:
        security.err("Resource not labeled")


def get_domain_label(configfile):
    # open the domain config file
    fd = None
    file = None
    if configfile[0] == '/':
        fd = open(configfile, "rb")
    else:
        for prefix in [".", "/etc/xen"]:
            file = prefix + "/" + configfile
            if os.path.isfile(file):
                fd = open(file, "rb")
                break
    if not fd:
        security.err("Configuration file '"+configfile+"' not found.")

    # read in the domain config file, finding the label line
    ac_entry_re = re.compile("^access_control\s*=.*", re.IGNORECASE)
    ac_exit_re = re.compile(".*'\].*")
    acline = ""
    record = 0
    for line in fd.readlines():
        if ac_entry_re.match(line):
            record = 1
        if record:
            acline = acline + line
        if record and ac_exit_re.match(line):
            record = 0
    fd.close()

    # send error message if we didn't find anything
    if acline == "":
        security.err("Domain not labeled")

    # print out the label
    (title, data) = acline.split("=", 1)
    data = data.strip()
    data = data.lstrip("[\'")
    data = data.rstrip("\']")
    print data


def main (argv):
    try:
        if len(argv) != 3:
            usage()

        if argv[1].lower() == "dom":
            configfile = argv[2]
            get_domain_label(configfile)
        elif argv[1].lower() == "res":
            resource = argv[2]
            get_resource_label(resource)
        else:
            usage()

    except security.ACMError:
        sys.exit(-1)

if __name__ == '__main__':
    main(sys.argv)


