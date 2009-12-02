import xen.lowlevel.xc
import XendDomain
import XendOptions
from XendLogging import log
from XendError import VmError

class MemoryPool:

    def init(self):
        xoptions = XendOptions.instance()
        self.default_reserved_memory = xoptions.get_reserved_memory() * 1024 * 1024 #KiB
        if self.default_reserved_memory <= 0:
            return
        self.enable_memory_pool = 1   
        self.dom0_ballooning = xoptions.get_enable_dom0_ballooning() 
        if not self.dom0_ballooning:
            return
        self.reserve_memory = 0 
        self.untouched_memory = 0
        #init reserved memory
        #if not reserve_memory_size: 
        xc = xen.lowlevel.xc.xc()
        physinfo = xc.physinfo()
        total_mem = physinfo['total_memory'] 
        if total_mem < self.reserve_memory:
            self.default_reserved_memory = total_mem
        self.reserve_memory = self.default_reserved_memory 
        self.untouched_memory = self.default_reserved_memory 
        log.debug("MemoryPool: init reserved_memory %d KiB" %self.reserve_memory)
            
    def __init__(self): 
        self.reserve_memory = 0 
        self.untouched_memory = 0
        self.default_reserved_memory = 0  
        self.enable_memory_pool = 0   
        self.dom0_ballooning = 0 
    def available_memory_check(self, need_mem):
        return self.is_enabled() and self.reserved_memory > need_mem

    def decrease_memory(self, value):
        if not self.is_enabled() or value <= 4096: #4M for PV guest kernel and ramdisk unzip
            return 
        elif self.reserve_memory < value: 
            raise VMError(('I need %d KiB, but only have %d KiB in Memory Pool') %(value,self.reserve_memory))
        else:
            self.reserve_memory -=  value
            log.debug("MemoryPool:  decrease_memory: decrease: %d reserved_memory %d KiB" %(value,self.reserve_memory))
        return

    def decrease_untouched_memory(self, value):
        if not self.is_enabled():
            return 
        elif self.untouched_memory < value: 
            raise VmError(('I need %d  KiB untouch mem, but only have %d KiB untouched mem in Memory Pool') %(value,self.reserve_memory))
        else:
            self.untouched_memory -= value
            log.debug("MemoryPool: decrease_untouched_memory: untouched_memory %d KiB" %self.untouched_memory)
        return

    def increase_memory(self, value):
        if not self.is_enabled():
            return  
        else:
            self.reserve_memory += value
            if self.reserve_memory > self.default_reserved_memory:
                raise VmError(('the maxsize of memory pool is %d KiB, but current is %d KiB') %(value,self.reserve_memory))
            log.debug("MemoryPool: increase_memory:%d, reserved_memory %d KiB" %(value,self.reserve_memory))
        return

    def is_enabled(self):
        return self.enable_memory_pool and self.dom0_ballooning
    
    def get_pool_size(self): 
        if self.is_enabled():
            return self.default_reserved_memory
        else:
            return 0

    def get_left_memory(self):
        if self.is_enabled():
            return self.reserve_memory
        else:
            return 0

    def get_untouched_memory(self):
        if self.is_enabled():
            return self.untouched_memory
        else:
            return 0

def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global MP_inst
    try:
        MP_inst
    except:
        MP_inst = MemoryPool()
        MP_inst.init()
    return MP_inst        
