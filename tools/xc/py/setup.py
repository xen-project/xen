
from distutils.core import setup, Extension

module = Extension("xc",
                   extra_compile_args   = ["-fno-strict-aliasing"],
                   include_dirs         = ["../lib"],
                   library_dirs         = ["../lib"],
                   libraries            = ["xc"],
                   sources              = ["Xc.c"])

setup(name = "xc",
      version = "1.0",
      ext_package = "xen.ext",
      ext_modules = [module])
