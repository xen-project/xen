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
# Copyright (C) 2009 flonatel GmbH & Co. KG
#============================================================================

import unittest

import utests.ut_util.ut_fileuri
import utests.ut_xend.ut_XendConfig
import utests.ut_xend.ut_image

suite = unittest.TestSuite(
    [utests.ut_util.ut_fileuri.suite(),
     utests.ut_xend.ut_XendConfig.suite(),
     utests.ut_xend.ut_image.suite(),
     ])

if __name__ == "__main__":
    testresult = unittest.TextTestRunner(verbosity=3).run(suite)

