
from distutils.core import setup, Extension
import sys

modules = [ 'xenctl.console_client', 'xenctl.utils' ]

# We need the 'tempfile' module from Python 2.3. We install this ourselves
# if the installed Python is older than 2.3.
major = sys.version_info[0]
minor = sys.version_info[1]
if major == 2 and minor < 3:
    modules.append('xenctl.tempfile')

setup(name = 'xenctl',
      version = '1.0',
      py_modules = modules,
      package_dir = { 'xenctl' : 'lib' },
      )

