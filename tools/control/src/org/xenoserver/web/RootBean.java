/*
 * RootBean.java
 * 03.05.05 aho creation
 */

package org.xenoserver.web;

import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionBindingListener;

import org.xenoserver.control.PartitionManager;
import org.xenoserver.control.Settings;
import org.xenoserver.control.VirtualDiskManager;
import org.xenoserver.control.XML;

public class RootBean implements HttpSessionBindingListener {
    static String state_filename_out = "/var/lib/xen/vdstate.xml";
    static String partition_filename = "/proc/partitions";
    static int default_sector_size = 512;

    PartitionManager pm;
    VirtualDiskManager vdm;

    public RootBean() {
        valueBound(null);
    }

    public void valueBound(HttpSessionBindingEvent event) {
        pm = PartitionManager.IT;
        vdm = VirtualDiskManager.IT;
        XML.loadState(pm, vdm, Settings.STATE_INPUT_FILE);
    }

    public void valueUnbound(HttpSessionBindingEvent event) {
        doFlushState();
    }

/*
    public int getPartitionCount() {
        return pm.getPartitionCount();
    }

    public Partition getPartition(int index) {
        return pm.getPartition(index);
    }

    public String doAddPartition(String partition, String chunksize) {
        Partition p = pm.get_partition(partition);
        String result = "done";
        int loop;
        long size;

        if (p == null) {
            return (" eh? what partition: " + partition);
        }

        size = Library.parse_size(chunksize) / default_sector_size;
        if (size == 0) {
            return ("error: invalid chunk size");
        }
        vdm.add_xeno_partition(p, size);
        pm.add_xeno_partition(p);

        return "done";
    }

    public int getVirtualDiskCount() {
        return vdm.getVirtualDiskCount();
    }

    public VirtualDisk getVirtualDisk(int index) {
        return vdm.getVirtualDisk(index);
    }

    public VirtualDisk getVirtualDiskKey(String key) {
        return vdm.get_virtual_disk_key(key);
    }

    public String doCreateVirtualDisk(String name, String size, long expiry) {
        VirtualDisk vd;
        Date date = new Date();
        long parse_size;

        parse_size = Library.parse_size(size) / default_sector_size;
        if (parse_size == 0) {
            return ("error: invalid size");
        }
        vd =
            vdm.create_virtual_disk(
                name,
                parse_size,
                new Date(date.getTime() + expiry));

        return ("Virtual Disk created with key: " + vd.get_key());

    }

    public String doDeleteVirtualDisk(String key) {
        if (key == null || key.trim().equals("")) {
            return ("error: no virtual disk specified");
        }
        vdm.delete_virtual_disk(key);

        return ("okay");
    }

    public String doRefreshVirtualDisk(String key, long expiry) {
        VirtualDisk vd = vdm.get_virtual_disk_key(key);
        Date date;
        String s = "";

        if (vd == null) {
            return ("disk not found: " + key);
        }
        s = vd.get_expiry().toString();
        date = new Date(vd.get_expiry().getTime() + expiry);
        vd.set_expiry(date);

        return ("okay " + expiry + " " + s + " " + date.toString());
    }

    public int getFreeExtentCount() {
        VirtualDisk free = vdm.getFreeVirtualDisk();
        return free.getExtentCount();
    }

    public Extent getFreeExtent(int index) {
        VirtualDisk free = vdm.getFreeVirtualDisk();
        return free.getExtent(index);
    }

    public Enumeration getVirtualBlockDevices() {
        return vdm.getVirtualBlockDevices();
    }

    public String doCreateVirtualBlockDevice(
        String vd_key,
        int domain,
        int vbd_num,
        String mode) {
        VirtualBlockDevice vbd;
        VirtualDisk vd;

        vbd = vdm.create_virtual_block_device(vd_key, domain, vbd_num, mode);
        if (vbd != null) {
            String command;
            FileWriter fw;

            vd = vdm.get_virtual_disk_key(vd_key);
            command = vd.dump_xen(vbd);

            try {
                fw = new FileWriter("/proc/xeno/dom0/vhd");
                fw.write(command);
                fw.flush();
                fw.close();
            } catch (Exception e) {
                return (e.toString());
            }
            return command;
        } else {
            return "Error encountered";
        }
    }

    public String doFlushVirtualBlockDevices() {
        vdm.flush_virtual_block_devices();
        return "done";
    }
*/
    public void doFlushState() {
        XML.saveState(pm, vdm, Settings.STATE_OUTPUT_FILE);
    }
}
