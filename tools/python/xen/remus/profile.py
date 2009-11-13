"""Simple profiling module
"""

import time

class ProfileBlock(object):
    """A section of code to be profiled"""
    def __init__(self, name):
        self.name = name

    def enter(self):
        print "PROF: entered %s at %f" % (self.name, time.time())

    def exit(self):
        print "PROF: exited %s at %f" % (self.name, time.time())

class NullProfiler(object):
    def enter(self, name):
        pass

    def exit(self, name=None):
        pass

class Profiler(object):
    def __init__(self):
        self.blocks = {}
        self.running = []

    def enter(self, name):
        try:
            block = self.blocks[name]
        except KeyError:
            block = ProfileBlock(name)
            self.blocks[name] = block

        block.enter()
        self.running.append(block)

    def exit(self, name=None):
        if name is not None:
            block = None
            while self.running:
                tmp = self.running.pop()
                if tmp.name == name:
                    block = tmp
                    break
                tmp.exit()
            if not block:
                raise KeyError('block %s not running' % name)
        else:
            try:
                block = self.running.pop()
            except IndexError:
                raise KeyError('no block running')

        block.exit()
