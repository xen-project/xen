/*
 * Partition.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

import java.io.PrintWriter;

/**
 * Represents a single real partition.
 */
public class Partition {
    /** Major device number as seen by Linux. */
    private int major;
    /** Minor device number as seen by Linux. */
    private int minor;
    /** Number of blocks in the partition. */
    private long blocks;
    /** Start sector of the partition. */
    private long start_sect;
    /** Number of sectors in the partition. */
    private long nr_sects;
    /** Name of the partition. */
    private String name;
    /** True if this partition is a XenoPartition. */
    private boolean xeno;

    /**
     * Mark this partition as a XenoPartition.
     */
    void makeXeno() {
        xeno = true;
    }

    /**
     * Constructor for Partition.
     * @param major Major number
     * @param minor Minor number
     * @param blocks Size in blocks
     * @param start_sect Start sector
     * @param nr_sects Number of sectors
     * @param name Name of partition
     * @param xeno True if XenoPartition
     */
    Partition(
        int major,
        int minor,
        long blocks,
        long start_sect,
        long nr_sects,
        String name,
        boolean xeno) {
        this.major = major;
        this.minor = minor;
        this.blocks = blocks;
        this.start_sect = start_sect;
        this.nr_sects = nr_sects;
        this.name = name;
        this.xeno = xeno;
    }

    /**
     * Dump this partition as XML.
     * @param out The writer to dump to.
     */
    void dumpAsXML(PrintWriter out) {
        out.println(
            "  <partition>\n"
                + "    <major>"
                + major
                + "</major>\n"
                + "    <minor>"
                + minor
                + "</minor>\n"
                + "    <blocks>"
                + blocks
                + "</blocks>\n"
                + "    <start_sect>"
                + start_sect
                + "</start_sect>\n"
                + "    <nr_sects>"
                + nr_sects
                + "</nr_sects>\n"
                + "    <name>"
                + name
                + "</name>\n"
                + "  </partition>");
    }

    /**
     * @return Major device number.
     */
    public int getMajor() {
        return major;
    }

    /**
     * @return Minor device number.
     */
    public int getMinor() {
        return minor;
    }

    /**
     * @return Number of blocks.
     */
    public long getBlocks() {
        return blocks;
    }

    /**
     * @return Starting sector.
     */
    public long getStartSect() {
        return start_sect;
    }

    /**
     * @return Number of sectors.
     */
    public long getNumSects() {
        return nr_sects;
    }

    /**
     * @return Name of partition.
     */
    public String getName() {
        return name;
    }

    /**
     * @return True if this is a XenoPartition.
     */
    public boolean isXeno() {
        return xeno;
    }

    /**
     * Is this partition identical to the other?
     * @param other Other partition to compare to.
     * @return True if they are identical.
     */
    public boolean identical(Partition other) {
        return this.major == other.major
            && this.minor == other.minor
            && this.blocks == other.blocks
            && this.start_sect == other.start_sect
            && this.nr_sects == other.nr_sects
            && this.name.equals(other.name);
    }

    /**
     * @return An Extent covering this partiton.
     */
    public Extent toExtent() {
        return new Extent(getDisk(),start_sect,nr_sects);
    }

    /**
     * @param e Extent to compare this partition to.
     * @return True if this partition covers the same disk area as the given extent.
     */
    public boolean matchesExtent(Extent e) {
        return e.getDisk() == getDisk()
            && e.getOffset() == start_sect
            && e.getSize() == nr_sects;
    }
    
    /**
     * @return Disk number for this partition.
     */
    public int getDisk() {
        if ( name.startsWith("hd") ) {
            // High 8 bits are major, low 8 bits are minor, with bottom 6 clear
            return (major << 8) | (minor & 0xC0); 
        } else if ( name.startsWith("sd") ) {
            // High 8 bits are major, low 8 bits are minor, with bottom 4 clear
            return (major << 8) | (minor & 0xF0);
        } else {
            throw new IllegalArgumentException("Don't know how to convert " + name + "into a disk number");
        }
    }
    
    /**
     * @return Partition index on disk for this partition.
     */
    public int getPartitionIndex() {
        if ( name.startsWith("hd") ) {
            // low 6 bits of minor are partition no
            return minor & 0x3F; 
        } else if ( name.startsWith("sd") ) {
            // low 4 bits of minor are partition no
            return minor & 0x0F;
        } else {
            throw new IllegalArgumentException("Don't know how to convert " + name + "into a partition number");
        }
    }
}
