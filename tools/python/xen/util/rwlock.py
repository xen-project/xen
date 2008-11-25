""" Reader-writer lock implementation based on a condition variable """

#============================================================================
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
# Copyright (C) 2008 International Business Machines Corp.
# Author: Stefan Berger <stefanb@us.ibm.com>
#============================================================================

from threading import Condition

class RWLock:

    RWLOCK_STATE_WRITER = -1
    RWLOCK_STATE_UNUSED = 0

    def __init__(self):
        self.__condition = Condition()
        self.__state = RWLock.RWLOCK_STATE_UNUSED
        self.__blocked_writers = 0

    def acquire_reader(self):
        self.__condition.acquire()
        while True:
            if self.__state == RWLock.RWLOCK_STATE_WRITER:
                self.__condition.wait()
            else:
                break
        self.__state += 1
        self.__condition.release()

    def acquire_writer(self):
        self.__condition.acquire()
        self.__acquire_writer(RWLock.RWLOCK_STATE_UNUSED)
        self.__condition.release()

    def __acquire_writer(self, wait_for_state):
        while True:
            if self.__state == wait_for_state:
                self.__state = RWLock.RWLOCK_STATE_WRITER
                break
            else:
                self.__blocked_writers += 1
                self.__condition.wait()
                self.__blocked_writers -= 1

    def release(self):
        self.__condition.acquire()
        if self.__state == RWLock.RWLOCK_STATE_WRITER:
            self.__state = RWLock.RWLOCK_STATE_UNUSED
        elif self.__state == RWLock.RWLOCK_STATE_UNUSED:
            assert False, 'Lock not in use.'
        else:
            self.__state -= 1
        self.__condition.notifyAll()
        self.__condition.release()


if __name__ == '__main__':
    from threading import Thread
    from time import sleep

    rwlock = RWLock()

    class Base(Thread):
        def __init__(self, name, timeout):
            self.name = name
            self.timeout = timeout
            Thread.__init__(self)

    class Reader(Base):
        def __init__(self, name = 'Reader', timeout = 10):
            Base.__init__(self, name, timeout)

        def run(self):
            print '%s begin' % self.name
            rwlock.acquire_reader()
            print '%s acquired' % self.name
            sleep(self.timeout)
            rwlock.release()
            print '%s end' % self.name

    class ReaderTwice(Base):
        def __init__(self, name = 'Reader', timeout = 10):
            Base.__init__(self, name, timeout)

        def run(self):
            print '%s begin' % self.name
            rwlock.acquire_reader()
            print '%s acquired once' % self.name
            sleep(self.timeout)
            rwlock.acquire_reader()
            print '%s acquired twice' % self.name
            sleep(self.timeout)
            rwlock.release()
            rwlock.release()
            print '%s end' % self.name

    class Writer(Base):
        def __init__(self, name = 'Writer', timeout = 10):
            Base.__init__(self, name, timeout)

        def run(self):
            print '%s begin' % self.name
            rwlock.acquire_writer()
            print '%s acquired' % self.name
            sleep(self.timeout)
            rwlock.release()
            print '%s end' % self.name

    def run_test(threadlist, msg):
        print msg
        for t in threadlist:
            t.start()
            sleep(1)
        for t in threads:
            t.join()
        print 'Done\n\n'

    threads = []
    threads.append( Reader('R1', 4) )
    threads.append( Reader('R2', 4) )
    threads.append( Writer('W1', 4) )
    threads.append( Reader('R3', 4) )
    run_test(threads,
             'Test: readers may bypass blocked writers')
