/*
 * VirtualDiskManager.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

import java.io.PrintWriter;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;

/**
 * VirtualDiskManager manages the list of virtual disks on the machine. It is
 * a Singleton which automatically initialises itself on first class reference.
 */
public class VirtualDiskManager {
    /** The single VDM reference. */
    public static final VirtualDiskManager IT = new VirtualDiskManager();
    /** The free-space disk. */
    private VirtualDisk freeDisk;
    /** The map of keys to virtual disks. */
    private LinkedHashMap virtualDisks = new LinkedHashMap(100);

    /**
     * VDM constructor, private as it's a singleton.
     */
    private VirtualDiskManager() {
        freeDisk = new VirtualDisk("free");
    }

    /**
     * Get the virtual disk with the specified key.
     * @param key The key to look for.
     * @return The virtual disk, or null if not found.
     */
    public VirtualDisk getVirtualDisk(String key) {
        return ((VirtualDisk) virtualDisks.get(key));
    }

    /**
     * Add a new partition to the free space list in the disk manager.
     * @param partition The partition to add.
     * @param chunkSize The chunk size to split the partition into, in sectors. 
     */
    void addPartition(Partition partition, long chunkSize) {
        freeDisk.addPartition(partition, chunkSize);
    }

    /**
     * Create a new virtual disk.
     * @param name The disk name to use.
     * @param size The number of sectors to allocate.
     * @param expiry The expiry time, or null for never.
     * @return null if not enough space is available
     */
    VirtualDisk createVirtualDisk(String name, long size, Date expiry) {
        if (freeDisk.getSize() < size) {
            return null;
        }

        VirtualDisk vd = new VirtualDisk(name, expiry);

        while (size > 0) {
            Extent e;

            e = freeDisk.removeExtent();
            if (e == null) {
                return null;
            }
            size -= e.getSize();
            vd.addExtent(e);
        }

        insertVirtualDisk(vd);

        return vd;
    }

    /**
     * Delete a virtual disk, and put its extents back into the free pool.
     * @param key The key of the disk to delete.
     */
    void deleteVirtualDisk(String key) {
        VirtualDisk vd;

        vd = (VirtualDisk) virtualDisks.get(key);
        if (vd != null) {
            Extent e;

            virtualDisks.remove(key);

            e = vd.removeExtent();
            while (e != null) {
                freeDisk.addExtent(e);
                e = vd.removeExtent();
            }
        }
    }

    /**
     * Insert a new virtual disk into the map.
     * @param vd The disk to insert.
     */
    void insertVirtualDisk(VirtualDisk vd) {
        virtualDisks.put(vd.getKey(), vd);
    }

    /**
     * Hash a virtual block device.
     * @param domain The VBD's domain.
     * @param vbdNum The VBD's number within the domain.
     * @return A suitable hash key.
     */
    Object hashVBD(int domain, int vbdNum) {
        return new Integer(domain * 16 + vbdNum);
    }

    /**
     * Set a new free disk.
     * @param vd The free disk to set.
     */
    void setFreeDisk(VirtualDisk vd) {
        freeDisk = vd;
    }

    /**
     * Dump the data in the VirtualDiskManager in XML form.
     * @param out The output writer to dump to.
     */
    void dumpAsXML(PrintWriter out) {
        out.println("<free>");
        freeDisk.dumpAsXML(out);
        out.println("</free>");
        out.println("<virtual_disks>");
        Iterator i = virtualDisks.values().iterator();
        while (i.hasNext()) {
            VirtualDisk vd = (VirtualDisk) i.next();
            vd.dumpAsXML(out);
        }
        out.println("</virtual_disks>");
    }

    /**
     * @return The free disk.
     */
    public VirtualDisk getFreeDisk() {
        return freeDisk;
    }

    /**
     * @return An iterator over the virtual disks.
     */
    public Iterator getVirtualDisks() {
        return virtualDisks.values().iterator();
    }
}
