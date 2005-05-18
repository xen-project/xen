import threading

def later(delay, fn, args=(), kwargs={}):
    """Schedule a function to be called later.

    @param _delay: delay in seconds
    @param _fn:    function
    @param args:   arguments (list)
    @param kwargs  keyword arguments (map)
    """
    timer = threading.Timer(delay, fn, args=args, kwargs=kwargs)
    timer.start()
    return timer

def now(fn, args=(), kwargs={}):
    """Schedule a function to be called now.

    @param _fn:    function
    @param args:   arguments (list)
    @param kwargs  keyword arguments (map)
    """
    thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
    thread.start()
    return thread
