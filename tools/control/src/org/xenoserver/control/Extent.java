/*
 * Extent.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

/**
 * Represents an extent on physical disk.
 */
public class Extent {
    /** Disk number; 16-bit major:minor pair with no partition number. */
    private int disk;
    /** Offset into disk in sectors. */
    private long offset;
    /** Size of extent in sectors. */
    private long size;
    /** Partition number, if one is allocated. */
    private int partition_no;

    /**
     * Constructor for Extent.
     * @param disk Disk number.
     * @param offset Offset into disk.
     * @param size Size of extent.
     */
    Extent(int disk, long offset, long size) {
        this.disk = disk;
        this.offset = offset;
        this.size = size;
    }
    
    /**
     * Constructor for Extent.
     * @param disk Disk number.
     * @param offset Offset into disk.
     * @param size Size of extent.
     * @param partition_no Partition number.
     */
    Extent(int disk, long offset, long size,int partition_no) {
        this.disk = disk;
        this.offset = offset;
        this.size = size;
        this.partition_no = partition_no;
    }

    /**
     * @return Disk number.
     */
    public int getDisk() {
        return disk;
    }

    /**
     * @return Offset into disk.
     */
    public long getOffset() {
        return offset;
    }

    /**
     * @return Size of extent.
     */
    public long getSize() {
        return size;
    }

    /**
     * @return Major number of disk.
     */
    public int getMajor() {
        return disk >> 8;
    }

    /**
     * @return Minor number of disk, not including partition.
     */
    public int getMinor() {
        return disk & 0xFF;
    }
    
    /**
     * @return Partition number of this extent.
     */
    public int getPartitionNo() {
        return partition_no;
    }
}
