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
# Copyright (C) 2005 XenSource Ltd
#============================================================================


def isCharConvertible(c):
    """Assert that the given value is convertible to a character using the %c
    conversion.  This implies that c is either an integer, or a character
    (i.e. a string of length 1).
    """
    
    assert (isinstance(c, int) or
            (isinstance(c, str) and
             len(c) == 1)), "%s is not convertible to a character" % c
