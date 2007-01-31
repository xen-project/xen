#===========================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2007 XenSource Ltd
#============================================================================

from xen.xend.XendAPIConstants import XEN_API_TASK_STATUS_TYPE
from xen.xend.XendLogging import log
import thread
import threading

class XendTask(threading.Thread):
    """Represents a Asynchronous Task used by Xen API.

    Basically proxies the callable object in a thread and returns the
    results via self.{type,result,error_code,error_info}.

    @cvar task_progress: Thread local storage for progress tracking.
                         It is a dict indexed by thread_id. Note that the
                         thread_id may be reused when the previous
                         thread with the thread_id ends.
                         
    @cvar task_progress_lock: lock on thread access to task_progress
    
    """

    # progress stack:
    # thread_id : [(start_task, end_task),
    #              (start_sub_task, end_sub_task)..]
    # example : (0, 100), (50, 100) (50, 100) ...
    #           That would mean that the task is 75% complete.
    #           as it is 50% of the last 50% of the task.
    
    task_progress = {}
    task_progress_lock = threading.Lock()

    def __init__(self, uuid, func, args, func_name, return_type, label, desc,
                 session):
        """
        @param uuid: UUID of the task
        @type uuid: string
        @param func: Method to call (from XendAPI)
        @type func: callable object
        @param args: arguments to pass to function
        @type args: list or tuple
        @param label: name label of the task.
        @type label: string
        @param desc: name description of the task.
        @type desc: string
        @param func_name: function name, eg ('VM.start')
        @type desc: string
        """
        
        threading.Thread.__init__(self)
        self.status_lock = threading.Lock()
        self.status = XEN_API_TASK_STATUS_TYPE[0]

        self.progress = 0
        self.type = return_type
        self.uuid = uuid
        
        self.result = None
        self.error_code = ''
        self.error_info = []
        
        self.name_label = label or func.__name__
        self.name_description = desc
        self.thread_id = 0

        self.func_name = func_name 
        self.func = func
        self.args = args

        self.session = session

    def set_status(self, new_status):
        self.status_lock.acquire()
        try:
            self.status = new_status
        finally:
            self.status_lock.release()

    def get_status(self):
        self.status_lock.acquire()
        try:
            return self.status
        finally:
            self.status_lock.release()        

    def run(self):
        """Runs the method and stores the result for later access.

        Is invoked by threading.Thread.start().
        """

        self.thread_id = thread.get_ident()
        self.task_progress_lock.acquire()
        try:
            self.task_progress[self.thread_id] = {}
            self.progress = 0            
        finally:
            self.task_progress_lock.release()

        try:
            result = self.func(*self.args)
            if result['Status'] == 'Success':
                self.result = result['Value']
                self.set_status(XEN_API_TASK_STATUS_TYPE[1])
            else:
                self.error_code = result['ErrorDescription'][0]
                self.error_info = result['ErrorDescription'][1:]
                self.set_status(XEN_API_TASK_STATUS_TYPE[2])                
        except Exception, e:
            log.exception('Error running Async Task')
            self.error_code = 'INTERNAL ERROR'
            self.error_info = [str(e)]
            self.set_status(XEN_API_TASK_STATUS_TYPE[2])

        self.task_progress_lock.acquire()
        try:
            del self.task_progress[self.thread_id]
            self.progress = 100
        finally:
            self.task_progress_lock.release()
    
    def get_record(self):
        """Returns a Xen API compatible record."""
        return {
            'uuid': self.uuid,            
            'name_label': self.name_label,
            'name_description': self.name_description,
            'status': self.status,
            'progress': self.get_progress(),
            'type': self.type,
            'result': self.result,
            'error_code': self.error_code,
            'error_info': self.error_info,
            'allowed_operations': {},
            'session': self.session,
        }

    def get_progress(self):
        """ Checks the thread local progress storage. """
        if self.status != XEN_API_TASK_STATUS_TYPE[0]:
            return 100
        
        self.task_progress_lock.acquire()
        try:
            # Pop each progress range in the stack and map it on to
            # the next progress range until we find out cumulative
            # progress based on the (start, end) range of each level
            start = 0
            prog_stack = self.task_progress.get(self.thread_id, [])[:]
            if len(prog_stack) > 0:
                start, stop = prog_stack.pop()
                while prog_stack:
                    new_start, new_stop = prog_stack.pop()
                    start = new_start + ((new_stop - new_start)/100.0 * start)

            # only update progress if it increases, this will prevent
            # progress from going backwards when tasks are popped off
            # the stack
            if start > self.progress:
                self.progress = int(start)
        finally:
            self.task_progress_lock.release()

        return self.progress


    def log_progress(cls, progress_min, progress_max,
                     func, *args, **kwds):
        """ Callable function wrapper that logs the progress of the
        function to thread local storage for task progress calculation.

        This is a class method so other parts of Xend will update
        the task progress by calling:

        XendTask.push_progress(progress_min, progress_max,
                               func, *args, **kwds)

        The results of the progress is stored in thread local storage
        and the result of the func(*args, **kwds) is returned back
        to the caller.

        """
        thread_id = thread.get_ident()
        retval = None

        # Log the start of the method
        cls.task_progress_lock.acquire()
        try:
            if type(cls.task_progress.get(thread_id)) != list:
                cls.task_progress[thread_id] = []
                    
            cls.task_progress[thread_id].append((progress_min,
                                                 progress_max))
        finally:
            cls.task_progress_lock.release()

        # Execute the method
        retval = func(*args, **kwds)

        # Log the end of the method by popping the progress range
        # off the stack.
        cls.task_progress_lock.acquire()
        try:
            cls.task_progress[thread_id].pop()
        finally:
            cls.task_progress_lock.release()

        return retval

    log_progress = classmethod(log_progress)

    

