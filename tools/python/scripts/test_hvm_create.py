#!/usr/bin/python

vm_cfg = {
    'name_label': 'API_HVM',
    'user_version': 1,
    'is_a_template': False,
    'auto_power_on': False, # TODO

    'memory_static_min': 64,    
    'memory_static_max': 128,
    #'memory_dynamic_min': 64,
    #'memory_dynamic_max': 128,
    
    
    'VCPUs_policy': 'credit',
    'VCPUs_params': {},
    'VCPUs_number': 2,

    'actions_after_shutdown': 'destroy',
    'actions_after_reboot': 'restart',
    'actions_after_crash': 'destroy',
    
    'PV_bootloader': '',
    'PV_bootloader_args': '',
    
    'PV_kernel': '',
    'PV_ramdisk': '',
    'PV_args': '',

    'HVM_boot': 'cda',
    'platform_std_VGA': False,
    'platform_serial': '',
    'platform_localtime': False,
    'platform_clock_offset': False,
    'platform_enable_audio': False,
    'PCI_bus': ''
}

local_vdi_cfg = {
    'name_label': 'gentoo.hvm',
    'name_description': '',
    'virtual_size': 0,
    'type': 'system',
    'parent': '',
    'SR_name': 'Local',
    'sharable': False,
    'read_only': False,
    'other_config': {'location': 'file:/root/gentoo.amd64.hvm.img'},
}    

local_vbd_cfg = {
    'VDI': '',
    'VM': '',
    'device': 'hda',
    'mode': 'RW',
    'type': 'disk',
    'driver': 'ioemu',
}

vif_cfg = {
    'name': 'API_VIF',
    'type': 'ioemu',
    'device': '',
    'network': '',
    'MAC': '',
    'MTU': 1500,
}    

console_cfg = {
    'protocol': 'rfb',
    'other_config': {'vncunused': 1, 'vncpasswd': 'testing'},
}


import sys
import time

from xapi import connect, execute

def test_vm_create():
    server, session = connect()
    vm_uuid = None
    local_vdi_uuid = None
    local_vbd_uuid = None
    vif_uuid = None
    
    # List all VMs
    vm_list = execute(server, 'VM.get_all', (session,))
    vm_names = []
    for vm_uuid in vm_list:
        vm_record = execute(server, 'VM.get_record', (session, vm_uuid))
        vm_names.append(vm_record['name_label'])

    # Get default SR
    local_sr_list = execute(server, 'SR.get_by_name_label',
                            (session, local_vdi_cfg['SR_name']))
    local_sr_uuid = local_sr_list[0]

    # Get default network
    net_list = execute(server, 'network.get_all', (session,))
    net_uuid = net_list[0]

    try:
        # Create a new VM
        print 'Create VM'
        vm_uuid = execute(server, 'VM.create', (session, vm_cfg))

        print 'Create VDI'
        # Create a new VDI (Local)
        local_vdi_cfg['SR'] = local_sr_uuid
        local_vdi_uuid = execute(server, 'VDI.create',
                                 (session, local_vdi_cfg))

        print 'Create VBD'
        # Create a new VBD (Local)
        local_vbd_cfg['VM'] = vm_uuid
        local_vbd_cfg['VDI'] = local_vdi_uuid
        local_vbd_uuid = execute(server, 'VBD.create',
                                 (session, local_vbd_cfg))

        print 'Craete VIF'
        # Create a new VIF
        vif_cfg['network'] = net_uuid
        vif_cfg['VM'] = vm_uuid
        vif_uuid = execute(server, 'VIF.create', (session, vif_cfg))

        # Create a console
        console_cfg['VM'] = vm_uuid
        console_uuid = execute(server, 'console.create',
                               (session, console_cfg))
        print console_uuid

        # Start the VM
        execute(server, 'VM.start', (session, vm_uuid, False))

        time.sleep(30)

        test_suspend = False
        if test_suspend:
            print 'Suspending VM..'
            execute(server, 'VM.suspend', (session, vm_uuid))
            print 'Suspended VM.'
            time.sleep(5)
            print 'Resuming VM ...'
            execute(server, 'VM.resume', (session, vm_uuid, False))
            print 'Resumed VM.'

        # Wait for user to say we're good to shut it down
        while True:
            destroy = raw_input('destroy VM? ')
            if destroy[0] in ('y', 'Y'):
                break

    finally:
        # Clean up
        if vif_uuid:
            execute(server, 'VIF.destroy', (session, vif_uuid))
            
        if local_vbd_uuid:
            execute(server, 'VBD.destroy', (session, local_vbd_uuid))
        if local_vdi_uuid:
            execute(server, 'VDI.destroy', (session, local_vdi_uuid))
            
        if vm_uuid:
            try:
                execute(server, 'VM.hard_shutdown', (session, vm_uuid))
                time.sleep(2)
            except:
                pass
            try:    
                execute(server, 'VM.destroy', (session, vm_uuid))
            except:
                pass


if __name__ == "__main__":
    test_vm_create()
    
