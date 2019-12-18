#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def open_file_or_fd(val, *argl, **kwargs):
    """
    If 'val' looks like a decimal integer, open it as an fd.  If not, try to
    open it as a regular file.
    """

    fd = -1
    try:
        # Does it look like an integer?
        fd = int(val, 10)
    except ValueError:
        pass

    # Try to open it...
    if fd != -1:
        return os.fdopen(fd, *argl, **kwargs)
    else:
        return open(val, *argl, **kwargs)
