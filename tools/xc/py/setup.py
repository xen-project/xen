
from distutils.core import setup, Extension

module = Extension("Xc",
                   include_dirs         = ["../lib"],
                   library_dirs         = ["../lib"],
                   sources              = ["xc_py.c"])

# Include the following line to link against shared libxc.so
#module.libraries = ["xc"]

# Include the following lines to link against static libxc.a
module.extra_objects = ["../lib/libxc.a"]
module.libraries     = ["z"]

setup(name = "Xc", version = "1.0", ext_modules = [module])
