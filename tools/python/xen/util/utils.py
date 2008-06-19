import traceback
import sys

def exception_string(e):
        (ty,v,tb) = sys.exc_info()
        return traceback.format_exception_only(ty,v)
