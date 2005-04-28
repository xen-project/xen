#
# Copyright 2005 Red Hat, Inc.
# Jeremy Katz <katzj@xxxxxxxxxx>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import os
import sys

fstypes = {}

def register_fstype(x):
    if x.name in fstypes.keys():
        return
    fstypes[x.name] = x

class FileSystemType(object):
    """A simple representation for a file system that gives a fs name
    and a method for sniffing a file to see if it's of the given fstype."""
    def __init__(self):
        self.name = ""

    def sniff_magic(self, fn, offset = 0):
        """Look at the filesystem at fn for the appropriate magic starting at
        offset offset."""
        raise RuntimeError, "sniff_magic not implemented"

    def open_fs(self, fn, offset = 0):
        """Open the given filesystem and return a filesystem object."""
        raise RuntimeError, "open_fs not implemented"

class FileSystem(object):
    def open(self, name, flags = 0, block_size = 0):
        """Open the fsys on name with given flags and block_size."""
        raise RuntimeError, "open not implemented"

    def close(self):
        """Close the fsys."""
        raise RuntimeError, "close not implemented"

    def open_file(self, file, flags = None):
        """Open the file 'name' with the given flags.  The returned object
        should look similar to a native file object."""
        raise RuntimeError, "open_file not implemented"
    
    def file_exist(self, file):
        """Check to see if the give file is existed.
        Return true if file existed, return false otherwise."""
        raise RuntimeError, "file_exist not implemented"

mydir = sys.modules['grub.fsys'].__path__[0]
for f in os.listdir(mydir):
    if not os.path.isdir("%s/%s" %(mydir, f)):
        continue
    try:
        exec "import grub.fsys.%s" %(f,)        
    except ImportError, e:
        pass
