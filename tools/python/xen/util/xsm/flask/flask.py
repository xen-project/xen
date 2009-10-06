import sys
import base64
from xen.lowlevel import flask
from xen.util import xsconstants
from xen.xend import sxp

#Functions exported through XML-RPC
xmlrpc_exports = [
  'on',
  'set_policy'
]


def err(msg):
    """Raise XSM-Flask exception.
    """
    sys.stderr.write("XSM-FlaskError: " + msg + "\n")
    raise XSMError(msg)

def on():
    return xsconstants.XS_POLICY_FLASK

def ssidref2label(ssidref):
    try:
        return flask.flask_sid_to_context(ssidref)
    except:
        return ""

def label2ssidref(label, policy, type):
    try:
        return flask.flask_context_to_sid(label)
    except:
       raise XSMError('Invalid context %s' % label)

def parse_security_label(security_label):
    return security_label

def calc_dom_ssidref_from_info(info):
    ssidref = label2ssidref(info['security_label'], "", "")
    return ssidref

def set_security_label(policy, label):
    if label:
        return label
    else:
        return ""

def ssidref2security_label(ssidref):
    label = ssidref2label(ssidref)
    return label

def get_security_label(self, xspol=None):
    label = self.info['security_label']
    return label

def set_policy(xs_type, policy_b64, flags=None, overwrite=None):
    policy = base64.b64decode(policy_b64);
    return flask.flask_load(policy), ""
