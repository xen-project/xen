
from distutils.core import setup, Extension

module = Extension("Xc",
                   include_dirs         = ["../lib"],
                   library_dirs         = ["../lib"],
                   libraries            = ["xc"],
                   sources              = ["Xc.c"])

setup(name = "Xc", version = "1.0", ext_modules = [module])
