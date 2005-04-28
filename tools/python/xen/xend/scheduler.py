import threading

class Scheduler:

    def __init__(self):
        self.lock = threading.Lock()
        self.schedule = {}

    def later(self, _delay, _name, _fn, args, kwargs={}):
        """Schedule a function to be called later (if not already scheduled).

        @param _delay: delay in seconds
        @param _name:  schedule name
        @param _fn:    function
        @param args:   arguments (list)
        @param kwargs  keyword arguments (map)
        """
        try:
            self.lock.acquire()
            if self.schedule.get(_name): return
            runargs = [ _name, _fn, args, kwargs ]
            timer = threading.Timer(_delay, self._run, args=runargs)
            self.schedule[_name] = timer
        finally:
            self.lock.release()
        timer.start()

    def cancel(self, name):
        """Cancel a scheduled function call.
        
        @param name: schedule name to cancel
        """
        timer = self._remove(name)
        if timer:
            timer.cancel()

    def _remove(self, name):
        try:
            self.lock.acquire()
            timer = self.schedule.get(name)
            if timer:
                del self.schedule[name]
            return timer
        finally:
            self.lock.release()

    def _run(self, name, fn, args, kwargs):
        self._remove(name)
        fn(*args, **kwargs)

        
