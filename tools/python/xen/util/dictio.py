#===========================================================================
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


def dict_read(dictname, filename):
    """Loads <filename> and returns the dictionary named <dictname> from
       the file.
    """
    dict = {}

    # read in the config file
    globs = {}
    locs = {}
    execfile(filename, globs, locs)

    for (k, v) in locs.items():
        if k == dictname:
            dict = v
            break

    return dict

def dict_write(dict, dictname, filename):
    """Writes <dict> to <filename> using the name <dictname>.  If the file
       contains any other data, it will be overwritten.
    """
    prefix = dictname + " = {\n"
    suffix = "}\n"
    fd = open(filename, "wb")
    fd.write(prefix)
    for key in dict:
        line = "    '" + str(key) + "': " + str(dict[key]) + ",\n"
        fd.write(line)
    fd.write(suffix)
    fd.close()
