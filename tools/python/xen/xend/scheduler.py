import threading

class Scheduler:

    def later(self, _delay, _fn, args=(), kwargs={}):
        """Schedule a function to be called later.

        @param _delay: delay in seconds
        @param _fn:    function
        @param args:   arguments (list)
        @param kwargs  keyword arguments (map)
        """
        runargs = [ _fn, args, kwargs ]
        timer = threading.Timer(_delay, self._run, args=runargs)
        timer.start()

    def now(self, _fn, args=(), kwargs={}):
        """Schedule a function to be called now.

        @param _fn:    function
        @param args:   arguments (list)
        @param kwargs  keyword arguments (map)
        """
        runargs = [ _fn, args, kwargs ]
        thread = threading.Thread(target=self._run, args=runargs)
        thread.start()

    def _run(self, fn, args, kwargs):
        fn(*args, **kwargs)
