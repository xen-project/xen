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

import threading

def later(delay, fn, args=(), kwargs={}):
    """Schedule a function to be called later.

    @param delay:  delay in seconds
    @param fn:     function
    @param args:   arguments (list)
    @param kwargs  keyword arguments (map)
    """
    timer = threading.Timer(delay, fn, args=args, kwargs=kwargs)
    timer.start()
    return timer

def now(fn, args=(), kwargs={}):
    """Schedule a function to be called now.

    @param fn:     function
    @param args:   arguments (list)
    @param kwargs  keyword arguments (map)
    """
    thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
    thread.start()
    return thread
