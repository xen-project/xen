/*
 * VirtualDisk.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

import java.io.PrintWriter;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

/**
 * A single virtual disk. This may be used by multiple virtual block devices.
 */
public class VirtualDisk {
    /** The name of this virtual disk. */
    private String name;
    /** The key of this virtual disk (unique). */
    private String key;
    /** The expiry time of this virtual disk, or null for never. */
    private Date expiry;
    /** The extent list for this virtual disk. */
    private Vector extents;

    /**
     * Construct a new virtual disk, specifying all parameters.
     * @param name Name of the new disk.
     * @param expiry Expiry time, or null for never.
     * @param key Key for the new disk, or null to autogenerate.
     */
    VirtualDisk(String name, Date expiry, String key) {
        this.name = name;
        if (key == null) {
            this.key = generateKey();
        } else {
            this.key = key;
        }
        this.expiry = expiry;
        extents = new Vector();
    }

    /**
     * Construct a new virtual disk, with automatically generated key and no expiry.
     * @param name Name of the new disk.
     */
    VirtualDisk(String name) {
        this(name, null, null);
    }

    /**
     * Construct a new virtual disk, with automatically generated key.
     * @param name Name of the new disk.
     * @param expiry Expiry time, or null for never.
     */
    VirtualDisk(String name, Date expiry) {
        this(name, expiry, null);
    }

    /**
     * Generate a unique key for this virtual disk.
     * For now, just generate a 10 digit number.
     * @return A unique key.
     */
    private static String generateKey() {
        return Long.toString(
            1000000000L + (long) (Math.random() * 8999999999L));
    }

    /**
     * Add an extent to this disk.
     * @param extent The extent to add.
     */
    void addExtent(Extent extent) {
        extents.add(extent);
    }

    /**
     * Remove the first extent from this disk.
     * @return The extent removed, or null if there are no extents.
     */
    Extent removeExtent() {
        Extent e;

        if (extents.size() > 0) {
            e = (Extent) extents.remove(0);
        } else {
            e = null;
        }

        return e;
    }

    /**
     * Form a string suitable for passing into the XenoLinux proc interface mapping
     * the given VBD to this virtual disk.
     * @param vbd The virtual block device to map.
     * @return A XenoLinux /proc string.
     */
    String dumpForXen(VirtualBlockDevice vbd) {
        StringBuffer sb = new StringBuffer();

        sb.append(
            "domain:"
                + vbd.getDomain()
                + " "
                + vbd.getMode().toString()
                + " "
                + "segment:"
                + vbd.getVbdNum()
                + " "
                + "extents:"
                + extents.size()
                + " ");
        for (int loop = 0; loop < extents.size(); loop++) {
            Extent e = (Extent) extents.get(loop);
            sb.append(
                "(disk:"
                    + e.getDisk()
                    + " "
                    + "offset:"
                    + e.getOffset()
                    + " "
                    + "size:"
                    + e.getSize()
                    + ")");
        }
        return sb.toString();
    }

    /**
     * Dump the virtual disk as XML.
     * @param out The writer to dump to.
     */
    void dumpAsXML(PrintWriter out) {
        out.println("  <virtual_disk>");
        out.println("    <name>" + name + "</name>");
        out.println("    <key>" + key + "</key>");
        if (expiry == null) {
            out.println("    <expiry>0</expiry>");
        } else {
            out.println("    <expiry>" + expiry.getTime() + "</expiry>");
        }
        out.println("    <extents>");
        for (int loop = 0; loop < extents.size(); loop++) {
            Extent e = (Extent) extents.get(loop);
            out.println("      <extent>");
            out.println("        <disk>" + e.getDisk() + "</disk>");
            out.println("        <size>" + e.getSize() + "</size>");
            out.println("        <offset>" + e.getOffset() + "</offset>");
            out.println("      </extent>");
        }
        out.println("    </extents>");
        out.println("  </virtual_disk>");

        return;
    }

    /**
     * Add a partition as a XenoPartition.
     * Chop the partition in to extents and add them to this virtual disk.
     * @param partition The partition to add.
     * @param extentSize The number of sectors to use for each extent. 
     */
    void addPartition(Partition partition, long extentSize) {
        int loop;

        for (loop = 0; loop < partition.getNumSects() / extentSize; loop++) {
            Extent extent =
                new Extent(
                    partition.getDisk(),
                    partition.getStartSect() + (extentSize * loop),
                    extentSize);

            addExtent(extent);
        }
    }

    /**
     * @return The name of this virtual disk.
     */
    public String getName() {
        return name;
    }

    /**
     * @return The key of this virtual disk.
     */
    public String getKey() {
        return key;
    }

    /**
     * @return The expiry time of this virtual disk.
     */
    public Date getExpiry() {
        return expiry;
    }

    /**
     * @return The number of extents in this virtual disk.
     */
    public int getExtentCount() {
        return extents.size();
    }

    /**
     * @return Total size of this virtual disk in sectors.
     */
    public long getSize() {
        long size = 0;
        Iterator i = extents.iterator();
        while (i.hasNext()) {
            size += ((Extent) i.next()).getSize();
        }
        return size;
    }

    /**
     * @return An iterator over all extents in the disk.
     */
    public Iterator extents() {
        return extents.iterator();
    }

    /**
     * Reset the expiry time for this virtual disk.
     * @param expiry The new expiry time, or null for never.
     */
    void refreshExpiry(Date expiry) {
        this.expiry = expiry;
    }
}
