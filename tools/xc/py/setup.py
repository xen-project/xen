
from distutils.core import setup, Extension

module = Extension("Xc",
                   extra_compile_args   = ["-fno-strict-aliasing"],
                   include_dirs         = ["../lib"],
                   library_dirs         = ["../lib"],
                   libraries            = ["xc"],
                   sources              = ["Xc.c"])

setup(name = "Xc", version = "1.0", ext_modules = [module])
