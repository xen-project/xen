#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2007
# Author: Stefan Berger <stefanb@us.ibm.com>

# Test to exercise the xspolicy and acmpolicy classes

from XmTestLib import xapi
from XmTestLib.XenAPIDomain import XmTestAPIDomain
from XmTestLib.acm import *
from XmTestLib import *
from xen.xend import XendAPIConstants
import xen.util.xsm.xsm as security
from xen.util import xsconstants
from xen.util.acmpolicy import ACMPolicy
from xen.xend.XendDomain import DOM0_UUID
import base64
import struct
import time

if not isACMEnabled():
    SKIP("Not running this test since ACM not enabled.")

try:
    session = xapi.connect()
except:
    SKIP("Skipping this test since xm is not using the Xen-API.")

def typestoxml(types):
    res = ""
    for t in types:
        res += "<Type>" + t + "</Type>\n"
    return res

def cfstoxml(cfss):
    res = ""
    for cfs in cfss:
        res += "<Conflict name=\"" + cfs['name'] + "\">\n" + \
               typestoxml(cfs['chws']) + \
               "</Conflict>\n"
    return res

def vmlabelstoxml(vmlabels, vmfrommap):
    res = ""
    for vmlabel in vmlabels:
        res += "<VirtualMachineLabel>\n"
        if vmlabel['name'] in vmfrommap:
            res += "<Name from=\""+ vmfrommap[vmlabel['name']] +"\">"
        else:
            res += "<Name>"
        res += vmlabel['name'] + "</Name>\n"
        res += "<SimpleTypeEnforcementTypes>\n" + \
                  typestoxml(vmlabel['stes']) + \
               "</SimpleTypeEnforcementTypes>\n"
        if vmlabel.has_key('chws'):
            res += "<ChineseWallTypes>\n" + \
                     typestoxml(vmlabel['chws']) + \
                   "</ChineseWallTypes>\n"
        res += "</VirtualMachineLabel>\n"
    return res


def reslabelstoxml(reslabels, resfrommap):
    res = ""
    for reslabel in reslabels:
        res += "<ResourceLabel>\n"
        if resfrommap.has_key(reslabel['name']):
            res += "<Name from=\""+ resfrommap[reslabel['name']] +"\">"
        else:
            res += "<Name>"
        res += reslabel['name'] + "</Name>\n"
        res += "<SimpleTypeEnforcementTypes>\n" + \
                  typestoxml(reslabel['stes']) + \
               "</SimpleTypeEnforcementTypes>\n"
        res += "</ResourceLabel>\n"
    return res

def create_xml_policy(hdr, stes, chws,
                      vmlabels, vmfrommap, bootstrap,
                      reslabels, resfrommap,
                      cfss):
    hdr_xml ="<PolicyHeader>\n" + \
             "  <PolicyName>" + hdr['name'] + "</PolicyName>\n" + \
             "  <Version>"    + hdr['version'] + "</Version>\n" + \
             "  <FromPolicy>\n" + \
             "    <PolicyName>" + hdr['oldname'] + "</PolicyName>\n" + \
             "    <Version>"    + hdr['oldversion'] + "</Version>\n" + \
             "  </FromPolicy>\n" + \
               "</PolicyHeader>\n"

    stes_xml = "<SimpleTypeEnforcement>\n" + \
               "  <SimpleTypeEnforcementTypes>\n" + \
                typestoxml(stes) + \
               "  </SimpleTypeEnforcementTypes>\n" + \
               "</SimpleTypeEnforcement>\n"

    chws_xml = "<ChineseWall>\n" + \
               "  <ChineseWallTypes>\n" + \
               typestoxml(chws) + \
               "  </ChineseWallTypes>\n" + \
               "  <ConflictSets>\n" + \
               cfstoxml(cfss) + \
               "  </ConflictSets>\n" + \
               "</ChineseWall>\n"

    subjlabel_xml = "<SubjectLabels bootstrap=\""+ bootstrap +"\">\n" + \
                     vmlabelstoxml(vmlabels, vmfrommap) + \
                    "</SubjectLabels>\n"
    objlabel_xml  = "<ObjectLabels>\n" + \
                      reslabelstoxml(reslabels, resfrommap) + \
                    "</ObjectLabels>\n"

    policyxml = "<?xml version=\"1.0\" ?>\n" + \
                "<SecurityPolicyDefinition xmlns=\"http://www.ibm.com\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.ibm.com ../../security_policy.xsd \">\n" + \
                hdr_xml + \
                stes_xml + \
                chws_xml + \
                "<SecurityLabelTemplate>\n" + \
                  subjlabel_xml + \
                  objlabel_xml + \
                "</SecurityLabelTemplate>\n" + \
                "</SecurityPolicyDefinition>\n"
    return policyxml


def update_hdr(hdr):
    """ Update the version information in the header """
    hdr['oldversion'] = hdr['version']
    hdr['oldname']    = hdr['name']
    vers = hdr['version']
    tmp = vers.split('.')
    if len(tmp) == 1:
        rev = 1
    else:
        rev = int(tmp[1]) + 1
    hdr['version'] = "%s.%s" % (tmp[0],rev)
    return hdr

session = xapi.connect()

policystate = session.xenapi.XSPolicy.get_xspolicy()

if policystate['repr'] != "":
    print "%s" % policystate['repr']
    try:
        acmpol = ACMPolicy(xml=policystate['repr'])
    except Exception, e:
        FAIL("Failure from creating ACMPolicy object: %s" % str(e))
    oldname = acmpol.policy_dom_get_hdr_item("PolicyName")
    oldvers = acmpol.policy_dom_get_hdr_item("Version")
    tmp = oldvers.split(".")
    if len(tmp) == 1:
        rev = 1
    else:
        rev = int(tmp[1]) + 1
    newvers = "%s.%s" % (tmp[0], str(rev))
    print "old name/version = %s/%s" % (oldname, oldvers)
else:
    oldname = None
    oldvers = None
    newvers = "1.0"

# Initialize the header of the policy
hdr = {}
hdr['name'] = "xm-test"
hdr['version'] = newvers

if oldname:
    hdr['oldname']    = oldname
    if oldvers and oldvers != "":
        hdr['oldversion'] = oldvers

stes = [ "SystemManagement", "red", "green", "blue" ]

chws = [ "SystemManagement", "red", "green", "blue" ]

bootstrap = "SystemManagement"

vm_sysmgt = { 'name' : bootstrap,
              'stes' : stes,
              'chws' : [ "SystemManagement" ] }

vm_red   = { 'name' : "red" ,
             'stes' : ["red"] ,
             'chws' : ["red"] }

vm_green = { 'name' : "green" ,
             'stes' : ["green"] ,
             'chws' : ["green"] }

vm_blue  = { 'name' : "blue" ,
             'stes' : ["blue"] ,
             'chws' : ["blue"] }

res_red   = { 'name' : "red" ,
              'stes' : ["red"] }

res_green = { 'name' : "green" ,
              'stes' : ["green"] }

res_blue  = { 'name' : "blue" ,
              'stes' : ["blue"] }

cfs_1 = { 'name' : "CFS1",
          'chws' : [ "red" , "blue" ] }

vmlabels = [ vm_sysmgt, vm_red, vm_green, vm_blue ]
vmfrommap = {}
reslabels = [ res_red, res_green, res_blue ]
resfrommap = {}
cfss = [ cfs_1 ]

vm_label_red    = xsconstants.ACM_POLICY_ID + ":xm-test:red"
vm_label_green  = xsconstants.ACM_POLICY_ID + ":xm-test:green"
vm_label_blue   = xsconstants.ACM_POLICY_ID + ":xm-test:blue"

xml = create_xml_policy(hdr, stes, chws,
                        vmlabels, vmfrommap, bootstrap,
                        reslabels, resfrommap,
                        cfss)

xml_good = xml

policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   xml,
                                                   xsconstants.XS_INST_LOAD,
                                                   True)

print "\n\npolicystate = %s" % policystate

policystate = session.xenapi.XSPolicy.get_xspolicy()

#
# Create two non-conflicting domains and start them
#
try:
    # XmTestAPIDomain tries to establish a connection to XenD
    domain1 = XmTestAPIDomain(extraConfig={ 'security_label' : vm_label_red })
except Exception, e:
    SKIP("Skipping test. Error: %s" % str(e))


vm1_uuid = domain1.get_uuid()

try:
    domain1.start(noConsole=True)
except:
    FAIL("Could not start domain1")

print "Domain 1 started"

try:
    # XmTestAPIDomain tries to establish a connection to XenD
    domain2 = XmTestAPIDomain(extraConfig={'security_label': vm_label_green })
except Exception, e:
    SKIP("Skipping test. Error: %s" % str(e))

vm2_uuid = domain2.get_uuid()

try:
    domain2.start(noConsole=True)
except:
    FAIL("Could not start domain1")


print "Domain 2 started"

# Try a policy that would put the two domains into conflict
cfs_2 = { 'name' : "CFS1",
          'chws' : [ "red" , "green" ] }
cfss = [ cfs_2 ]

hdr = update_hdr(hdr)
xml = create_xml_policy(hdr, stes, chws,
                        vmlabels, vmfrommap, bootstrap,
                        reslabels, resfrommap,
                        cfss)

policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   xml,
                                                   xsconstants.XS_INST_LOAD,
                                                   True)

print "policystate %s" % policystate

if int(policystate['xserr']) == 0:
    FAIL("(1) Should not have been able to set this policy.")

if len(policystate['errors']) == 0:
    FAIL("Hypervisor should have reported errros.")

errors = base64.b64decode(policystate['errors'])

print "Length of errors: %d" % len(errors)
a,b = struct.unpack("!ii",errors)

print "%08x , %08x" % (a,b)

#
# Create a faulty policy with 'red' STE missing
#

cfss = [ cfs_1 ]
stes = [ "SystemManagement", "green", "blue" ]

xml = create_xml_policy(hdr, stes, chws,
                        vmlabels, vmfrommap, bootstrap,
                        reslabels, resfrommap,
                        cfss)
policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   xml,
                                                   xsconstants.XS_INST_LOAD,
                                                   True)

print "Result from setting faulty(!) policy with STE 'red' missing:"
print "policystate %s" % policystate

if int(policystate['xserr']) == 0:
    FAIL("(2) Should not have been able to set this policy.")

#
# Create a policy with 'red' VMLabel missing -- should not work since it is
# in use.
#
stes = [ "SystemManagement", "red", "green", "blue" ]

vmlabels = [ vm_sysmgt, vm_green, vm_blue ]

xml = create_xml_policy(hdr, stes, chws,
                        vmlabels, vmfrommap, bootstrap,
                        reslabels, resfrommap,
                        cfss)
policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   xml,
                                                   xsconstants.XS_INST_LOAD,
                                                   True)
print "Result from setting faulty(!) policy with VMlabel 'red' missing:"
print "policystate %s" % policystate

if int(policystate['xserr']) == 0:
    FAIL("(3) Should not have been able to set this policy.")

#
# Create a policy with 'blue' VMLabel missing -- should work since it is NOT
# in use.
#
vmlabels = [ vm_sysmgt, vm_red, vm_green ]

xml = create_xml_policy(hdr, stes, chws,
                        vmlabels, vmfrommap, bootstrap,
                        reslabels, resfrommap,
                        cfss)
policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   xml,
                                                   xsconstants.XS_INST_LOAD,
                                                   True)

print "Result from setting (good) policy with VMlabel 'blue' missing:"
print "policystate %s" % policystate

if int(policystate['xserr']) != 0:
    FAIL("(4) Should have been able to set this policy: %s" % xml)

#
# Move the green VMLabel towards blue which should put the running
# domain with label blue into a conflict set
#
vmlabels = [ vm_sysmgt, vm_red, vm_blue ]

vmfrommap = { "blue" : "green" }  #  new : old

hdr = update_hdr(hdr)  #Needed, since last update was successful
xml = create_xml_policy(hdr, stes, chws,
                        vmlabels, vmfrommap, bootstrap,
                        reslabels, resfrommap,
                        cfss)

policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   xml,
                                                   xsconstants.XS_INST_LOAD,
                                                   True)

print "policystate %s" % policystate

if int(policystate['xserr']) == 0:
    FAIL("(5) Should not have been able to set this policy.")

#
# Try to install a policy where a VM label has a faulty VM label name
#
vmfrommap = {}

vm_blue_bad = { 'name' : "blue:x" ,   # ':' no allowed
                'stes' : ["blue"],
                'chws' : ["blue"] }

vmlabels = [ vm_sysmgt, vm_red, vm_green, vm_blue_bad ]

xml = create_xml_policy(hdr, stes, chws,
                        vmlabels, vmfrommap, bootstrap,
                        reslabels, resfrommap,
                        cfss)

policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   xml,
                                                   xsconstants.XS_INST_LOAD,
                                                   True)

print "policystate %s" % policystate

if int(policystate['xserr']) == 0:
    FAIL("(6) Should not have been able to set this policy.")

#
# End the test by installing the initial policy again
#

cur_version = hdr['version']
(maj, min) = cur_version.split(".")
cur_version = "%s.%s" % (maj, str(int(min)-1) )

orig_acmpol = ACMPolicy(xml=xml_good)
orig_acmpol.set_frompolicy_version(cur_version)
orig_acmpol.set_policy_version(hdr['version'])

policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                                                   orig_acmpol.toxml(),
                                                   xsconstants.XS_INST_LOAD,
                                                   True)

if int(policystate['xserr']) != 0:
    FAIL("(END) Should have been able to set this policy.")

domain1.stop()
domain2.stop()
domain1.destroy()
domain2.destroy()
