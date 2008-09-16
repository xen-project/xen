import sys
from xen.util import xsconstants
from xen.xend.XendLogging import log

class XSMError(Exception):
    def __init__(self,value):
        self.value = value
    def __str__(self):
        return repr(self.value)


security_dir_prefix = "";
policy_dir_prefix = "";
active_policy = "";
NULL_SSIDREF = 0;

#Functions exported through XML-RPC
xmlrpc_exports = [
  'set_resource_label',
  'get_resource_label',
  'list_labels',
  'get_labeled_resources',
  'set_policy',
  'reset_policy',
  'get_policy',
  'activate_policy',
  'rm_bootpolicy',
  'get_xstype',
  'get_domain_label',
  'set_domain_label'
]

def err(msg):
    """Raise XSM-dummy exception.
    """
    raise XSMError(msg)

def on():
    return 0

def ssidref2label(ssidref):
    return 0

def label2ssidref(label, policy, type):
    return 0

def res_security_check(resource, domain_label):
    return 1

def get_res_security_details(resource):
    return ("","","")

def get_res_label(resource):
    return ("","")

def res_security_check_xapi(rlabel, rssidref, rpolicy, xapi_dom_label):
    return 1

def parse_security_label(security_label):
    return ""

def calc_dom_ssidref_from_info(info):
    return ""

def set_security_label(policy, label):
    return ""

def ssidref2security_label(ssidref):
    return ""

def has_authorization(ssidref):
    return True

def get_security_label(self, xspol=None):
    return ""

def get_resource_label_xapi(resource):
    return ""

def get_labeled_resources_xapi():
    return {}

def set_resource_label_xapi(resource, reslabel_xapi, oldlabel_xapi):
    err("Command not supported under XSM 'dummy' module.")

def format_resource_label(res):
    return ""

def set_resource_label(resource, policytype, policyref, reslabel,
                       oreslabel = None):
    err("Command not supported under XSM 'dummy' module.")

def get_resource_label(resource):
    return ""

def list_labels(policy_name, ltype):
    return []

def get_labeled_resources():
    return {}

def set_policy(xs_type, xml, flags, overwrite):
    err("Command not supported under xsm 'dummy' module.")

def reset_policy():
    err("Command not supported under xsm 'dummy' module.")

def get_policy():
    return "", 0

def activate_policy():
    err("Command not supported under xsm 'dummy' module.")

def rm_bootpolicy():
    err("Command not supported under xsm 'dummy' module.")

def get_xstype():
    return 0

def get_domain_label(domain):
    return ""

def set_domain_label():
    err("Command not supported under xsm 'dummy' module.")

def dump_policy():
    pass

def dump_policy_file():
    pass

def get_ssid(domain):
    err("No ssid has been assigned to any domain under xsm dummy module.")

def security_label_to_details(res_label):
    return ("","","")
