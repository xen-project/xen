from xen.xend.sv.XendClientDeferred import server
from xen.xend import sxp

def getDomInfoHash( domain ):
    deferred = server.xend_domain( int( domain ) )
    deferred.addCallback( procDomInfo, domain )
    return deferred
    
def procDomInfo( domInfo, domain ):
    d = {}
    d['dom']    = int( domain )
    d['name']   = sxp.child_value( domInfo, 'name' )
    d['mem']    = int( sxp.child_value( domInfo, 'memory' ) )
    d['cpu']    = int( sxp.child_value( domInfo, 'cpu' ) )
    d['state']  = sxp.child_value( domInfo, 'state' )
    d['cpu_time'] = float( sxp.child_value( domInfo, 'cpu_time' ) )
    if( sxp.child_value( domInfo, 'up_time' ) ):
        d['up_time'] =  float( sxp.child_value( domInfo, 'up_time' ) )
    if( sxp.child_value( domInfo, 'start_time' ) ):
        d['start_time'] = float( sxp.child_value( domInfo, 'start_time' ) )
    return d
    
def bigTimeFormatter( time ):
    weeks = time // 604800
    remainder = time % 604800
    days = remainder // 86400
    
    remainder = remainder % 86400

    hms = smallTimeFormatter( remainder )
    
    return "%d weeks, %d days, %s" % ( weeks, days, hms )

def smallTimeFormatter( time ):
    hours = time // 3600
    remainder = time % 3600
    mins = remainder // 60
    secs = time % 60
    return "%02d:%02d:%04.1f (hh:mm:ss.s)" % ( hours, mins, secs ) 

def stateFormatter( state ):
    states = [ 'Running', 'Blocked', 'Paused', 'Shutdown', 'Crashed' ]
    
    for i in range( len( state ) ):
        if state[i] != "-":
            return states[ i ] + " (%s)" % state
    
    return state
    
def memoryFormatter( mem ):
    return "%7dMb" % mem

def cpuFormatter( mhz ):
    if mhz > 1000:
        ghz = float( mhz ) / 1000.0
        return "%4.2fGHz" % ghz
    else:
        return "%4dMHz" % mhz
        
def hyperthreadFormatter( threads ):
    if int( threads ) > 1:
        return "Yes (%d)" % threads
    else:
        return "No"