/*
 * VirtualBlockDevice.java
 * 03.03.27 aho creation
 */

package org.xenoserver.control;

/**
 * A virtual block device; a mapping from a domain-specific number to a virtual
 * disk with associated access mode.
 */
public class VirtualBlockDevice {
    /** The virtual disk which this block device maps onto. */
    private VirtualDisk vd;
    /** The domain in which this block device exists. */
    private int domain;
    /** The block device number in that domain. */
    private int vbdNum;
    /** The access mode within that domain. */
    private Mode mode;

    /**
     * Constructor for VirtualBlockDevice.
     * @param vd The virtual disk to map to.
     * @param domain The domain to create the device in.
     * @param vbdNum The number for the device.
     * @param mode The access mode.
     */
    VirtualBlockDevice(
        VirtualDisk vd,
        int domain,
        int vbdNum,
        Mode mode) {
        this.vd = vd;
        this.domain = domain;
        this.vbdNum = vbdNum;
        this.mode = mode;
    }

    /**
     * @return This device's virtual disk.
     */
    public VirtualDisk getVirtualDisk() {
        return vd;
    }

    /**
     * @return The domain this device exists in.
     */
    public int getDomain() {
        return domain;
    }

    /**
     * @return The device number within its domain.
     */
    public int getVbdNum() {
        return vbdNum;
    }

    /**
     * @return This device's access mode.
     */
    public Mode getMode() {
        return mode;
    }
}
