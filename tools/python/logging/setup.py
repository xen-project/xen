#============================================================================
# Install the logging package from python 2.3 if not present.
#============================================================================
import os

try:
    import logging
except ImportError:
    print 'logging package not found: installing'
    os.chdir('logging-0.4.9.2')
    execfile('setup.py')
