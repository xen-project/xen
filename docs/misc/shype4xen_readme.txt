Copyright: IBM Corporation (C)
20 June 2005
Author: Reiner Sailer

This document is a very short introduction into the sHype access control 
security architecture implementation and how it is perceived by users. It 
is a very preliminary draft  for the courageous ones to get "their feet wet" 
and to be able to give feedback (via the xen-devel/xense-devel mailing lists).

Install:

cd into xeno-unstable.bk 
(use --dry-run option if you want to test the patch only)
patch -p1 -g0 < *tools.diff
patch -p1 -g0 < *xen.diff

(no rejects, probably some line offsets)

make uninstall; make mrproper; make; ./install.sh should install the default 
sHype into Xen (rebuild your initrd images if necessary). Reboot.

Debug output: there are two triggers for debug output:
a) General sHype debug:
    xeno-unstable.bk/xen/include/public/acm.h
    undefine ACM_DEBUG to switch this debug off

b) sHype enforcement hook trace: This prints a small trace for each enforcement 
hook that is executed. The trigger is in
    xeno-unstable.bk/xen/include/acm/acm_hooks.h
    undefine ACM_TRACE_MODE to switch this debug off

1. The default NULL policy
***************************
When you apply the patches and startup xen, you should at first not notice any 
difference because the default policy is the "NULL" policy, which as the name 
implies does not enforce anything.

However, when you try

[root@laptop policy]# xm list
Name              Id  Mem(MB)  CPU  State  Time(s)  Console  SSID-REF
Domain-0           0      620   0  r----     25.6            default

You might detect a new parameter "SSID-REF" displayed for domains. This 
parameter describes the subject security identifier reference of the domain. It 
is shown as "default" since there is no policy to be enforced.

To display the currently enforced policy, use the policy tool under xeno-
unstable.bk/tools/policy: policy_tool getpolicy. You should see output like the 
one below.

[root@laptop policy]#./policy_tool getpolicy

Policy dump:
============
Magic     = 1debc.
PolVer    = aaaa0000.
Len       = 14.
Primary   = NULL policy (c=0, off=14).
Secondary = NULL policy (c=0, off=14).
No primary policy (NULL).
No secondary policy (NULL).

Policy dump End.

Since this is a dump of a binary policy, it's not pretty. The important parts 
are the "Primary" and "Secondary" policy fields set to "NULL policy". sHype 
currently allows to set two independent policies; thus the two SSID-REF parts 
shown in 'xm list'. Right here: primary policy only means this policy is 
checked first, the secondary policy is checked if the primary results in 
"permitted access". The result of the combined policy is "permitted" if both 
policies return permitted (NULL policy always returns permitted). The result is 
"denied" if at least one of the policies returns "denied". Look into xeno-
unstable.bk/xen/include/acm/acm_hooks.h for the general hook structure 
integrating the policy decisions (if you like, you won't need it for the rest 
of the Readme file).

2. Setting Chinese Wall and Simple Type Enforcement policies:
*************************************************************

We'll get fast to the point. However, in order to understand what we are doing, 
we must at least understand the purpose of the policies that we are going to 
enforce. The two policies presented here are just examples and the 
implementation encourages adding new policies easily.

2.1. Chinese Wall policy: "decides whether a domain can be started based on 
this domain's ssidref and the ssidrefs of the currently running domains". 
Generally, the Chinese wall policy allows specifying certain types (or classes 
or categories, whatever the preferred word) that conflict; we usually assign a 
type to a workload and the set of types of those workloads running in a domain 
make up the type set for this domain.  Each domain is assigned a set of types 
through its SSID-REF (we register Chinese Wall as primary policy, so the 
ssidref used for determining the Chinese Wall types is the one annotated with 
"p:" in xm list) since each SSID-REF points at a set of types. We'll see how 
SSIDREFs are represented in Xen later when we will look at the policy. (A good 
read for Chinese Wall is: Brewer/Nash The Chinese Wall Security Policy 1989.)

So let's assume the Chinese Wall policy we are running distinguishes 10 types: 
t0 ... t9. Let us assume further that each SSID-REF points to a set that 
includes exactly one type (attached to domains that run workloads of a single 
type). SSID-REF 0 points to {t0}, ssidref 1 points to {t1} ... 9 points to 
{t9}. [This is actually the example policy we are going to push into xen later]

Now the Chinese Wall policy allows you to define "Conflict type sets" and it 
guarantees that of any conflict set at most one type is "running" at any time. 
As an example, we have defined 2 conflict set: {t2, t3} and {t0, t5, t6}. 
Specifying these conflict sets, sHype ensures that at most one type of each set 
is running (either t2 or t3 but not both; either t0 or t5 or t6 but not 
multiple of them).

The effect is that administrators can define which workload types cannot run 
simultaneously on a single Xen system. This is useful to limit the covert 
timing channels between such payloads or to ensure that payloads don't 
interfere with each other through existing resource dependencies.

2.2. Simple Type Enforcement (ste) policy: "decides whether two domains can 
share data, e.g., setup event channels or grant tables to each other, based on 
the two domains' ssidref. This, as the name says, is a simple policy. Think of 
each type as of a single color. Each domain has one or more colors, i.e., the 
domains ssid for the ste policy points to a set that has set one or multiple 
types. Let us assume in our example policy we differentiate 5 colors (types) 
and define 5 different ssids referenced by ssidref=0..4. Each ssid shall have 
exactly one type set, i.e., describes a uni-color. Only ssid(0) has all types 
set, i.e., has all defined colors.

Sharing is enforced by the ste policy by requiring that two domains that want 
to establish an event channel or grant pages to each other must have a common 
color. Currently all domains communicate through DOM0 by default; i.e., Domain0 
will necessarily have all colors to be able to create domains (thus, we will 
assign ssidref(0) to Domain0 in our example below.

More complex mandatory access control policies governing sharing will follow; 
such policies are more sophisticated than the "color" scheme above by allowing 
more flexible (and complex :_) access control decisions than "share a color" or 
"don't share a color" and will be able to express finer-grained policies.


2.3 Binary Policy:
In the future, we will have a policy tool that takes as input a more humane 
policy description, using types such as development, home-banking, donated-
Grid, CorpA-Payload ... and translates the respective policy into what we see 
today as the binary policy using 1s and 0s and sets of them. For now, we must 
live with the binary policy when working with sHype.

    
2.4 Exemplary use of a real sHype policy on Xen. To activate a real policy, 
edit the file (yes, this will soon be a compile option):
  xeno-unstable.bk/xen/include/public/acm.h
  Change: #define ACM_USE_SECURITY_POLICY ACM_NULL_POLICY
   To : #define ACM_USE_SECURITY_POLICY ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY
   cd xeno-unstable.bk
   make mrproper
   make uninstall (manually remove /etc/xen.old if necessary)
   make
   ./install.sh      (recreate your kernel initrd's if necessary)
   Reboot into new xen.gz
     
After booting, check out 'xm dmesg'; should show somewhere in the middle:

(XEN) acm_init: Enforcing Primary CHINESE WALL policy, Secondary SIMPLE TYPE 
ENFORCEMENT policy.

Even though you can activate those policies in any combination and also 
independently, the policy tool currently only supports setting the policy for 
the above combination.

Now look at the minimal startup policy with:
                xeno-unstable.bk/tools/policytool getpolicy

You should see something like:

[root@laptop policy]# ./policy_tool getpolicy

Policy dump:
============
Magic     = 1debc.
PolVer    = aaaa0000.
Len       = 36.
Primary   = CHINESE WALL policy (c=1, off=14).
Secondary = SIMPLE TYPE ENFORCEMENT policy (c=2, off=2c).


Chinese Wall policy:
====================
Max Types     = 1.
Max Ssidrefs  = 1.
Max ConfSets  = 1.
Ssidrefs Off  = 10.
Conflicts Off = 12.
Runing T. Off = 14.
C. Agg. Off   = 16.

SSID To CHWALL-Type matrix:

   ssidref 0:  00 

Confict Sets:

   c-set 0:    00 

Running
Types:         00 

Conflict
Aggregate Set: 00 


Simple Type Enforcement policy:
===============================
Max Types     = 1.
Max Ssidrefs  = 1.
Ssidrefs Off  = 8.

SSID To STE-Type matrix:

   ssidref 0: 01 


Policy dump End.

This is a minimal policy (of little use), except it will disable starting any 
domain that does not have ssidref set to 0x0. The Chinese Wall policy has 
nothing to enforce and the ste policy only knows one type, which is set for the 
only defined ssidref.

The item that defines the ssidref in a domain configuration is:

ssidref = 0x12345678

Where ssidref is interpreted as a 32bit number, where the lower 16bits become 
the ssidref for the primary policy and the higher 16bits become the ssidref for 
the secondary policy. sHype currently supports two policies but this is an 
implementation decision and can be extended if necessary.

This reference defines the security information of a domain. The meaning of the 
SSID-REF depends on the policy, so we explain it when we explain the real 
policies.


Setting a new Security Policy:
******************************
The policy tool with all its current limitations has one usable example policy 
compiled-in. Please try at this time to use the setpolicy command:
       xeno-unstable.bk/tools/policy/policy_tool setpolicy

You should see a dump of the policy you are setting. It should say at the very 
end: 

Policy successfully set.

Now try to dump the currently enforced policy, which is the policy we have just 
set and the dynamic security state information of this policy 
(<<< ... some additional explanations)

[root@laptop policy]# ./policy_tool getpolicy

Policy dump:
============
Magic     = 1debc.
PolVer    = aaaa0000.
Len       = 112.
Primary   = CHINESE WALL policy (c=1, off=14).
Secondary = SIMPLE TYPE ENFORCEMENT policy (c=2, off=d8).


Chinese Wall policy:
====================
Max Types     = a.
Max Ssidrefs  = 5.
Max ConfSets  = 2.
Ssidrefs Off  = 10.
Conflicts Off = 74.
Runing T. Off = 9c.
C. Agg. Off   = b0.

SSID To CHWALL-Type matrix:

   ssidref 0:  01 00 00 00 00 00 00 00 00 00  <<< type0 is set for ssidref0
   ssidref 1:  00 01 00 00 00 00 00 00 00 00 
   ssidref 2:  00 00 01 00 00 00 00 00 00 00 
   ssidref 3:  00 00 00 01 00 00 00 00 00 00 
   ssidref 4:  00 00 00 00 01 00 00 00 00 00  <<< type4 is set for ssidref4
                                              <<< types 5-9 are unused
Confict Sets:

   c-set 0:    00 00 01 01 00 00 00 00 00 00  <<< type2 and type3 never run together
   c-set 1:    01 00 00 00 00 01 01 00 00 00  <<< only one of types 0, 5 or 6 
                                              <<<   can run simultaneously
Running
Types:         01 00 00 00 00 00 00 00 00 00  <<< ref-count for types of running domains

Conflict
Aggregate Set: 00 00 00 00 00 01 01 00 00 00  <<< aggregated set of types that                  
                                              <<< cannot run because they 
                                              <<< are in conflict set 1 and
                                              <<< (domain 0 is running w t0)
                                             

Simple Type Enforcement policy:
===============================
Max Types     = 5.
Max Ssidrefs  = 5.
Ssidrefs Off  = 8.

SSID To STE-Type matrix:

   ssidref 0: 01 01 01 01 01                  <<< ssidref0 points to a set that                  
                                              <<< has all types set (colors)
   ssidref 1: 00 01 00 00 00                  <<< ssidref1 has color1 set
   ssidref 2: 00 00 01 00 00                  <<< ...
   ssidref 3: 00 00 00 01 00 
   ssidref 4: 00 00 00 00 01 


Policy dump End.


This is a small example policy with which we will demonstrate the enforcement.

Starting Domains with policy enforcement
========================================
Now let us play with this policy. 

Define 3 or 4 domain configurations. I use the following config using a ramdisk 
only and about 8MBytes of memory for each DomU (test purposes):

#-------configuration xmsec1-------------------------
kernel = "/boot/vmlinuz-2.6.11-xenU"
ramdisk="/boot/U1_ramdisk.img"
#security reference identifier
ssidref= 0x00010001
memory = 10
name = "xmsec1"
cpu = -1   # leave to Xen to pick
# Number of network interfaces. Default is 1.
nics=1
dhcp="dhcp"
#-----------------------------------------------------

xmsec2 and xmsec3 look the same except for the name and the ssidref line. Use 
your domain config file and add "ssidref = 0x00010001" to the first (xmsec1),  
"ssidref= 0x00020002" to the second (call it xmsec2), and "ssidref=0x00030003"  
to the third (we will call this one xmsec3).

First start xmsec1: xm create -c xmsec1 (succeeds)

Then
[root@laptop policy]# xm list 
Name              Id  Mem(MB)  CPU  State  Time(s)  Console  SSID-REF
Domain-0           0      620   0  r----     42.3            s:00/p:00
xmnosec            1        9   0  -b---      0.3    9601    s:00/p:05
xmsec1             2        9   0  -b---      0.2    9602    s:01/p:01

Shows a new domain xmsec1 running with primary (here: chinese wall) ssidref 1 
and secondary (here: simple type enforcement) ssidref 1. The ssidrefs are  
independent and can differ for a domain.

[root@laptop policy]# ./policy_tool getpolicy

Policy dump:
============
Magic     = 1debc.
PolVer    = aaaa0000.
Len       = 112.
Primary   = CHINESE WALL policy (c=1, off=14).
Secondary = SIMPLE TYPE ENFORCEMENT policy (c=2, off=d8).


Chinese Wall policy:
====================
Max Types     = a.
Max Ssidrefs  = 5.
Max ConfSets  = 2.
Ssidrefs Off  = 10.
Conflicts Off = 74.
Runing T. Off = 9c.
C. Agg. Off   = b0.

SSID To CHWALL-Type matrix:

   ssidref 0:  01 00 00 00 00 00 00 00 00 00
   ssidref 1:  00 01 00 00 00 00 00 00 00 00
   ssidref 2:  00 00 01 00 00 00 00 00 00 00
   ssidref 3:  00 00 00 01 00 00 00 00 00 00
   ssidref 4:  00 00 00 00 01 00 00 00 00 00

Confict Sets:

   c-set 0:    00 00 01 01 00 00 00 00 00 00
   c-set 1:    01 00 00 00 00 01 01 00 00 00   <<< t1 is not part of any c-set

Running
Types:         01 01 00 00 00 00 00 00 00 00   <<< xmsec1 has ssidref 1->type1
                  ^^                           <<< ref-count at position 1 incr
Conflict
Aggregate Set: 00 00 00 00 00 01 01 00 00 00   <<< domain 1 was allowed to       
                                               <<< start since type 1 was not
                                               <<< in conflict with running 
                                               <<< types
                                            
Simple Type Enforcement policy:
===============================
Max Types     = 5.
Max Ssidrefs  = 5.
Ssidrefs Off  = 8.

SSID To STE-Type matrix:

   ssidref 0: 01 01 01 01 01           <<< the ste policy does not maintain; we
   ssidref 1: 00 01 00 00 00   <--     <<< see that domain xmsec1 has ste 
   ssidref 2: 00 00 01 00 00           <<< ssidref1->type1 and has this type in
   ssidref 3: 00 00 00 01 00           <<< common with dom0
   ssidref 4: 00 00 00 00 01


Policy dump End.

Look at sHype output in xen dmesg:

[root@laptop xen]# xm dmesg
.
.
[somewhere near the very end]
(XEN) chwall_init_domain_ssid: determined chwall_ssidref to 1.
(XEN) ste_init_domain_ssid.
(XEN) ste_init_domain_ssid: determined ste_ssidref to 1.
(XEN) acm_init_domain_ssid: Instantiated individual ssid for domain 0x01.
(XEN) chwall_post_domain_create.
(XEN) ste_pre_eventchannel_interdomain.
(XEN) ste_pre_eventchannel_interdomain: (evtchn 0 --> 1) common type #01.
(XEN) shype_authorize_domops.
(XEN) ste_pre_eventchannel_interdomain.
(XEN) ste_pre_eventchannel_interdomain: (evtchn 0 --> 1) common type #01.
(XEN) ste_pre_eventchannel_interdomain.
(XEN) ste_pre_eventchannel_interdomain: (evtchn 0 --> 1) common type #01.


You can see that the chinese wall policy does not complain and that the ste 
policy makes three access control decisions for three event-channels setup 
between domain 0 and the new domain 1. Each time, the two domains share the 
type1 and setting up the eventchannel is permitted.


Starting up a second domain xmsec2:

[root@laptop xen]# xm create -c xmsec2
Using config file "xmsec2".
Started domain xmsec2, console on port 9602
************ REMOTE CONSOLE: CTRL-] TO QUIT ********
Linux version 2.6.11-xenU (root@laptop.home.org) (gcc version 3.4.2 20041017 
(Red Hat 3.4.2-6.fc3)) #1 Wed Mar 30 13:14:31 EST 2005
.
.
.
[root@laptop policy]# xm list
Name              Id  Mem(MB)  CPU  State  Time(s)  Console  SSID-REF
Domain-0           0      620   0  r----     71.7            s:00/p:00
xmsec1             1        9   0  -b---      0.3    9601    s:01/p:01
xmsec2             2        7   0  -b---      0.3    9602    s:02/p:02   << our domain runs both policies with ssidref 2


[root@laptop policy]# ./policy_tool getpolicy

Policy dump:
============
Magic     = 1debc.
PolVer    = aaaa0000.
Len       = 112.
Primary   = CHINESE WALL policy (c=1, off=14).
Secondary = SIMPLE TYPE ENFORCEMENT policy (c=2, off=d8).


Chinese Wall policy:
====================
Max Types     = a.
Max Ssidrefs  = 5.
Max ConfSets  = 2.
Ssidrefs Off  = 10.
Conflicts Off = 74.
Runing T. Off = 9c.
C. Agg. Off   = b0.

SSID To CHWALL-Type matrix:

   ssidref 0:  01 00 00 00 00 00 00 00 00 00
   ssidref 1:  00 01 00 00 00 00 00 00 00 00
   ssidref 2:  00 00 01 00 00 00 00 00 00 00   <<< our domain has type 2 set
   ssidref 3:  00 00 00 01 00 00 00 00 00 00
   ssidref 4:  00 00 00 00 01 00 00 00 00 00

Confict Sets:

   c-set 0:    00 00 01 01 00 00 00 00 00 00   <<< t2 is in c-set0 with type 3
   c-set 1:    01 00 00 00 00 01 01 00 00 00

Running
Types:         01 01 01 00 00 00 00 00 00 00   <<< t2 is running since the 
                     ^^                        <<< current aggregate conflict
                                               <<< set (see above) does not 
                                               <<< include type 2
Conflict
Aggregate Set: 00 00 00 01 00 01 01 00 00 00   <<< type 3 is added to the 
                                               <<< conflict aggregate


Simple Type Enforcement policy:
===============================
Max Types     = 5.
Max Ssidrefs  = 5.
Ssidrefs Off  = 8.

SSID To STE-Type matrix:

   ssidref 0: 01 01 01 01 01
   ssidref 1: 00 01 00 00 00
   ssidref 2: 00 00 01 00 00
   ssidref 3: 00 00 00 01 00
   ssidref 4: 00 00 00 00 01


Policy dump End.


The sHype xen dmesg output looks similar to the one above when starting the 
first domain.

Now we start xmsec3 and it has ssidref3. Thus, it tries to run as type3 which 
conflicts with running type2 (from xmsec2). As expected, creating this domain 
fails for security policy enforcement reasons.

[root@laptop xen]# xm create -c xmsec3
Using config file "xmsec3".
Error: Error creating domain: (22, 'Invalid argument')
[root@laptop xen]#

[root@laptop xen]# xm dmesg
.
.
[somewhere near the very end]
(XEN) chwall_pre_domain_create.
(XEN) chwall_pre_domain_create: CHINESE WALL CONFLICT in type 03.

xmsec3 ssidref3 points to type3, which is in the current conflict aggregate 
set. This domain cannot start until domain xmsec2 is destroyed, at which time 
the aggregate conflict set is reduced and type3 is excluded from it. Then, 
xmsec3 can start. Of course, afterwards, xmsec2 cannot be restarted. Try it.

3. Policy tool
**************
toos/policy/policy_tool.c

a) ./policy_tool getpolicy
      prints the currently enforced policy
      (see for example section 1.)

b) ./policy_tool setpolicy
      sets a predefined and hardcoded security
      policy (the one described in section 2.)

c) ./policy_tool dumpstats
      prints some status information about the caching
      of access control decisions (number of cache hits
      and number of policy evaluations for grant_table
      and event channels).

d) ./policy_tool loadpolicy <binary_policy_file>
      sets the policy defined in the <binary_policy_file>
      please use the policy_processor that is posted to this
      mailing list to create such a binary policy from an XML
      policy description

4. Policy interface:
********************
The Policy interface is working in "network-byte-order" (big endian). The reason for this
is that policy files/management should be portable and independent of the platforms.

Our policy interface enables managers to create a single binary policy file in a trusted
environment and distributed it to multiple systems for enforcement.

====================end-of file=======================================