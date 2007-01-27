import unittest

import xen.xend.XendConfig as XendConfig


class test_XendConfig(unittest.TestCase):

    def testParseFromSXP(self):
        cfg = XendConfig.XendConfig(
            sxp_obj = (
            ['vm',
             ['bootloader_args', '-q --default_args="root=/dev/sda1 ro" --extra_args="quiet" /images/VM1.sda'],
                       ['bootloader', '/usr/bin/pygrub'],
             ['device', ['vif', ['mac', '00:16:3E:4C:D1:00'], ['script', 'vif-bridge'], ['bridge', 'xenbr0']]],
             ['device', ['vif', ['mac', '00:16:3E:48:56:26'], ['script', 'vif-bridge'], ['bridge', 'vbridge0']]],
             ['device', ['vbd', ['uname', 'phy:/images/VM1.sda'], ['dev', 'sda'], ['mode', 'w']]],
             ['device', ['vbd', ['uname', 'phy:/images/VM1.sdb'], ['dev', 'sdb'], ['mode', 'w']]],
             ['memory', '256'], ['name', 'VM1'], ['on_crash', 'restart'],
             ['uuid', '10927a76-fe27-49b2-8f57-2970b7bbed6c'], ['vcpus', '1']
             ]))

        self.assertEqual(cfg['uuid'], '10927a76-fe27-49b2-8f57-2970b7bbed6c')
        self.assertEqual(cfg['name_label'], 'VM1')
        self.assertEqual(cfg['memory_static_max'], 256)

        ordered_refs = cfg.ordered_device_refs()
        self.assertEqual(cfg['devices'][ordered_refs[0]][0], 'vbd')
        self.assertEqual(cfg['devices'][ordered_refs[1]][0], 'vbd')
        self.assertEqual(cfg['devices'][ordered_refs[2]][0], 'vif')
        self.assertEqual(cfg['devices'][ordered_refs[3]][0], 'vif')
        self.assertEqual(cfg['devices'][ordered_refs[0]][1]['uname'],
                         'phy:/images/VM1.sda')
        self.assertEqual(cfg['devices'][ordered_refs[1]][1]['uname'],
                         'phy:/images/VM1.sdb')
        self.assertEqual(cfg['devices'][ordered_refs[2]][1]['mac'],
                         '00:16:3E:4C:D1:00')
        self.assertEqual(cfg['devices'][ordered_refs[3]][1]['mac'],
                         '00:16:3E:48:56:26')


def test_suite():
    return unittest.makeSuite(test_XendConfig)
