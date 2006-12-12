#============================================================================
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (c) 2006 XenSource Inc.
#============================================================================

import errno
import os
import os.path
import stat


def parents(dir, perms, enforcePermissions = False):
    """
    Ensure that the given directory exists, creating it if necessary, but not
    complaining if it's already there.
    
    @param dir The directory name.
    @param perms One of the stat.S_ constants.
    @param enforcePermissions Enforce our ownership and the given permissions,
    even if the directory pre-existed with different ones.
    """
    # Catch the exception here, rather than checking for the directory's
    # existence first, to avoid races.
    try:
        os.makedirs(dir, perms)
    except OSError, exn:
        if exn.args[0] != errno.EEXIST or not os.path.isdir(dir):
            raise
    if enforcePermissions:
        os.chown(dir, os.geteuid(), os.getegid())
        os.chmod(dir, stat.S_IRWXU)
