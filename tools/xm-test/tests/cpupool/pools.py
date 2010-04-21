#!/usr/bin/python


from XmTestLib import *

def checkRequirements():
    # - min 4 cpus
    # - only Pool-0 defined
    nr_cpus = int(getInfo("nr_cpus"))
    if nr_cpus < 4:
        SKIP("Need at least 4 cpus for pool tests")
    if len(getPoolList()) > 1:
        SKIP("More than one pool already defined")

    # reduce Pool-0 to CPU-0
    traceCommand("xm pool-cpu-add Pool-0 0")
    for i in range(1, nr_cpus):
        traceCommand("xm pool-cpu-remove Pool-0 %s" % i)

def createStdPool(add_param=None):
    cmd = "xm pool-create pool1.cfg "
    if add_param:
        for k,v in add_param.items():
            cmd += "%s=%s " % (k,v)
    status, output = traceCommand(cmd)
    if status != 0 or "Traceback" in output:
        raise XmError("xm failed", trace=output, status=status)

def deletePool(name):
    cmd = "xm pool-delete %s" % name
    status, output = traceCommand(cmd)
    if status != 0 or "Traceback" in output:
        raise XmError("xm failed", trace=output, status=status)

def destroyPool(name, delete_on_xenapi=False):
    cmd = "xm pool-destroy %s" % name
    status, output = traceCommand(cmd)
    if status != 0 or "Traceback" in output:
        raise XmError("xm failed", trace=output, status=status)
    if os.getenv("XM_USES_API") and delete_on_xenapi:
        deletePool(name)

def getPoolList():
    status, output = traceCommand("xm pool-list")
    if status != 0 or "Traceback" in output:
        raise XmError("xm failed", trace=output, status=status)
    lines = output.splitlines()
    pools = []
    for l in lines[1:]:
        elms = l.split(" ", 1)
        pools.append(elms[0]);
    return pools

def domInPool(dom, pool):
    cmd = "xm list --pool=%s" % pool
    status, output = traceCommand(cmd)
    if status != 0 or "Traceback" in output:
        raise XmError("xm failed", trace=output, status=status)
    return re.search(dom, output) != None

def migrateToPool(dom, pool):
    status, output = traceCommand("xm pool-migrate %s %s" % (dom, pool))
    if status != 0 or "Traceback" in output:
        raise XmError("xm failed", trace=output, status=status)
    return domInPool(dom, pool)

def cleanupPoolsDomains():
    destroyAllDomUs()
    for pool in getPoolList():
        if pool != 'Pool-0':
            destroyPool(pool, True)

def waitForDomain(name):
    for i in range(10):
        if not isDomainRunning(name):
            break
        time.sleep(1)

