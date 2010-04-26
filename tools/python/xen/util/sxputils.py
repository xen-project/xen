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
# Copyright (c) 2009 Fujitsu Technology Solutions
#============================================================================

""" convert sxp to map / map to sxp.
"""

import types
from xen.xend import sxp

def map2sxp(map_val):
    """ conversion of all key-value pairs of a map (recursively) to sxp.
        @param map_val: map; if a value contains a list or dict it is also
                    converted to sxp
        @type map_val: dict
        @return sxp expr
        @rtype: list
    """
    sxp_vals = []
    for (k, v) in map_val.items():
        if isinstance(v, types.DictionaryType):
            sxp_vals += [[k] + map2sxp(v)]
        elif isinstance(v, types.ListType):
            sxp_vals += [[k] + v]
        else:
            sxp_vals += [[k, v]]
    return sxp_vals

def sxp2map( s ):
    """ conversion of sxp to map.
        @param s: sxp expr
        @type s:  list
        @return: map
        @rtype: dict
    """
    sxphash = {}

    for child in sxp.children( s ):
        if isinstance( child, types.ListType ) and len( child ) > 1:
            if isinstance( child[1], types.ListType ) and len( child[1] ) > 1:
                sxphash[ child[0] ] = sxp2map( child )
            else:
                childs = sxp.children(child)
                if len(childs) > 1:
                    sxphash[ child[0] ] = childs
                else:
                    sxphash[ child[0] ] = childs[0]

    return sxphash


