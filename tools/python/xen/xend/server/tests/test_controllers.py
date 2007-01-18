import os
import re
import unittest

import xen.xend.XendOptions

xen.xend.XendOptions.XendOptions.config_default = '/dev/null'

from xen.xend.server import netif


FAKE_DOMID = 42
FAKE_DEVID = 63


xoptions = xen.xend.XendOptions.instance()


class test_controllers(unittest.TestCase):

    def testNetif(self):
        controller = self.controllerInstance(netif.NetifController)

        self.assertNetif(controller.getDeviceDetails({}), None)
        self.assertNetif(
            controller.getDeviceDetails({'mac': 'aa:bb:cc:dd:ee:ff'}),
            'aa:bb:cc:dd:ee:ff')



    def assertNetif(self, results, expectedMac):

        (devid, backdets, frontdets) = results

        self.assertEqual(devid, FAKE_DEVID)

        self.assertEqual(backdets['handle'], str(FAKE_DEVID))
        self.assertEqual(backdets['script'],
                         os.path.join(xoptions.network_script_dir,
                                      xoptions.get_vif_script()))
        self.assertValidMac(backdets['mac'], expectedMac)

        self.assertEqual(frontdets['handle'], str(FAKE_DEVID))
        self.assertValidMac(frontdets['mac'], expectedMac)


    MAC_REGEXP = re.compile('^' +
                            ':'.join([r'[0-9a-f][0-9a-f]'
                                      for i in range(0, 6)]) +
                            '$')

    def assertValidMac(self, mac, expected):
        if expected:
            self.assertEqual(mac, expected)
        else:
            self.assert_(self.MAC_REGEXP.match(mac))
            

    def controllerInstance(self, cls):
        """Allocate an instance of the given controller class, and override
        methods as appropriate so that we can run tests without needing
        Xenstored."""
        
        result = cls(FakeXendDomainInfo())

        result.allocateDeviceID = fakeID

        return result


class FakeXendDomainInfo:
    def getDomainPath(self):
        return "/test/fake/domain/%d/" % FAKE_DOMID


def fakeID():
    return FAKE_DEVID


def test_suite():
    return unittest.makeSuite(test_controllers)
