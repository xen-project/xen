from threading import Timer

from unix import listenUNIX, connectUNIX
from tcp import listenTCP, connectTCP

def callLater(_delay, _fn, *args, **kwds):
    timer = Timer(_delay, _fn, args=args, kwargs=kwds)
    timer.start()
    return timer
