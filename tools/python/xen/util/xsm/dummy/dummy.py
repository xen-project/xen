import sys

class XSMError(Exception):
    def __init__(self,value):
        self.value = value
    def __str__(self):
        return repr(self.value)

security_dir_prefix = "";
policy_dir_prefix = "";
active_policy = "";
NULL_SSIDREF = 0;

def err(msg):
    """Raise XSM-dummy exception.
    """
    sys.stderr.write("XSM-dummyError: " + msg + "\n")
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
