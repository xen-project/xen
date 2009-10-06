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
# Copyright (C) 2007 International Business Machines Corp.
# Author: Stefan Berger <stefanb@us.ibm.com>
#============================================================================

XS_INST_NONE = 0
XS_INST_BOOT = (1 << 0)
XS_INST_LOAD = (1 << 1)

XS_POLICY_ACM = (1 << 0)
XS_POLICY_FLASK = (1 << 1)
XS_POLICY_DUMMY  = (1 << 2)
XS_POLICY_USE = 0

# Some internal variables used by the Xen-API
ACM_LABEL_VM  = (1 << 0)
ACM_LABEL_RES = (1 << 1)

# Base for XS error codes for collision avoidance with other error codes
XSERR_BASE = 0x1000

# XS error codes as used by the Xen-API
XSERR_SUCCESS                  =  0
XSERR_GENERAL_FAILURE          =  1 + XSERR_BASE
XSERR_BAD_XML                  =  2 + XSERR_BASE  # XML is wrong (not according to schema)
XSERR_XML_PROCESSING           =  3 + XSERR_BASE
XSERR_POLICY_INCONSISTENT      =  4 + XSERR_BASE  # i.e., bootstrap name not a VM label
XSERR_FILE_ERROR               =  5 + XSERR_BASE
XSERR_BAD_RESOURCE_FORMAT      =  6 + XSERR_BASE  # badly formatted resource
XSERR_BAD_LABEL_FORMAT         =  7 + XSERR_BASE
XSERR_RESOURCE_NOT_LABELED     =  8 + XSERR_BASE
XSERR_RESOURCE_ALREADY_LABELED =  9 + XSERR_BASE
XSERR_WRONG_POLICY_TYPE        = 10 + XSERR_BASE
XSERR_BOOTPOLICY_INSTALLED     = 11 + XSERR_BASE
XSERR_NO_DEFAULT_BOOT_TITLE    = 12 + XSERR_BASE
XSERR_POLICY_LOAD_FAILED       = 13 + XSERR_BASE
XSERR_POLICY_LOADED            = 14 + XSERR_BASE
XSERR_POLICY_TYPE_UNSUPPORTED  = 15 + XSERR_BASE
XSERR_BAD_CONFLICTSET          = 16 + XSERR_BASE
XSERR_RESOURCE_IN_USE          = 17 + XSERR_BASE
XSERR_BAD_POLICY_NAME          = 18 + XSERR_BASE
XSERR_VERSION_PREVENTS_UPDATE  = 19 + XSERR_BASE
XSERR_BAD_LABEL                = 20 + XSERR_BASE
XSERR_VM_WRONG_STATE           = 21 + XSERR_BASE
XSERR_POLICY_NOT_LOADED        = 22 + XSERR_BASE
XSERR_RESOURCE_ACCESS          = 23 + XSERR_BASE
XSERR_HV_OP_FAILED             = 24 + XSERR_BASE
XSERR_BOOTPOLICY_INSTALL_ERROR = 25 + XSERR_BASE
XSERR_VM_NOT_AUTHORIZED        = 26 + XSERR_BASE
XSERR_VM_IN_CONFLICT           = 27 + XSERR_BASE
XSERR_POLICY_HAS_DUPLICATES    = 28 + XSERR_BASE
XSERR_LAST                     = 28 + XSERR_BASE ## KEEP LAST

XSERR_MESSAGES = [
    '',
    'General Failure',
    'XML is malformed',
    'Error while processing XML',
    'Policy has inconsistencies',
    'A file access error occurred',
    'The resource format is not valid',
    'The label format is not valid',
    'The resource is not labeld',
    'The resource is already labeld',
    'The policy type is wrong',
    'The system boot policy is installed',
    'Could not find the default boot title',
    'Loading of the policy failed',
    'The policy is loaded',
    'The policy type is unsupported',
    'There is a bad conflict set',
    'The resource is in use',
    'The policy has an invalid name',
    'The version of the policy prevents an update',
    'The label is bad',
    'Operation not premittend - the VM is in the wrong state',
    'The policy is not loaded',
    'Error accessing resource',
    'Operation failed in hypervisor',
    'Boot policy installation error',
    'VM is not authorized to run',
    'VM label conflicts with another VM',
    'Duplicate labels or types in policy'
]

def xserr2string(err):
    if err == XSERR_SUCCESS:
        return "Success"
    if err >= XSERR_GENERAL_FAILURE and \
       err <= XSERR_LAST:
        return XSERR_MESSAGES[err - XSERR_BASE]
    return "Unknown XSERR code '%s'." % (hex(err))

# Policy identifiers used in labels
ACM_POLICY_ID = 'ACM'
FLASK_POLICY_ID = 'FLASK'

INVALID_POLICY_PREFIX = 'INV_'

INVALID_SSIDREF = 0xFFFFFFFFL

XS_INACCESSIBLE_LABEL = '__INACCESSIBLE__'
