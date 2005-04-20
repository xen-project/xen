import threading

class Scheduler:

    def __init__(self):
        self.lock = threading.Lock()
        self.schedule = {}

    def later(self, _delay, _name, _fn, args):
        """Schedule a function to be called later (if not already scheduled).

        @param _delay: delay in seconds
        @param _name:  schedule name
        @param _fn:    function
        @param args:   arguments
        """
        try:
            self.lock.acquire()
            if self.schedule.get(_name): return
            timer = threading.Timer(_delay, _fn, args=args)
            self.schedule[_name] = timer
        finally:
            self.lock.release()
        timer.start()

    def cancel(self, name):
        """Cancel a scheduled function call.
        
        @param name: schedule name to cancel
        """
        try:
            self.lock.acquire()
            timer = self.schedule.get(name)
            if not timer:
                return
            del self.schedule[name]
        finally:
            self.lock.release()
        timer.cancel()

        
