/*
 * PartitionManager.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;

/**
 * PartitionManager manages the partitions on the machine. It is a Singleton
 * which automatically initialises itself on first class reference.
 */
public class PartitionManager {
    /** The proc header string, used to check that this is a suitable proc file. */
    private static final String PROC_TEMPLATE =
        "major minor start_sector  num_sectors name";

    /** The single PartitionManager reference. */
    public static final PartitionManager IT =
        new PartitionManager(Settings.PARTITIONS_FILE);

    /** The list of partitions. */
    private Vector partition_map;

    /**
     * Initialize partition manager with source file.
     * Normally we read from /proc/partitions, but we can
     * specify an alternative file for debugging.
     * @param filename The file to read partition data from.
     */
    private PartitionManager(String filename) {
        String str;
        BufferedReader in;

        partition_map = new Vector(100, 10);

        try {
            in = new BufferedReader(new FileReader(filename));

            str = in.readLine(); /* skip headings */
            if (str.length() < PROC_TEMPLATE.length()
                || !str.substring(0, PROC_TEMPLATE.length()).equals(
                    PROC_TEMPLATE)) {
                System.err.println("Error: Incorrect /proc/partitions.");
                System.err.println("       Is this Xeno?");
                System.exit(1);
            }

            str = in.readLine(); /* skip blank line */

            str = in.readLine();
            while (str != null) {
                Partition partition =
                    new Partition(
                        Integer.parseInt(str.substring( 0,  5).trim()),
                        Integer.parseInt(str.substring( 6, 11).trim()),
                        Integer.parseInt(str.substring(25, 37).trim())/2,
                        Integer.parseInt(str.substring(12, 24).trim()),
                        Integer.parseInt(str.substring(25, 37).trim()),
                        str.substring(38).trim(),
                        false);

                partition_map.add(partition);
                str = in.readLine();
            }
        } catch (IOException io) {
            System.err.println(
                "PartitionManager: error reading partition file ["
                    + filename
                    + "]");
            System.err.println(io);
        }
    }

    /**
     * Find a partition with the specified name.
     * @param name The name to search for.
     * @return The partition found, or null if no such partition.
     */
    public Partition getPartition(String name) {
        Partition partition = null;
        for (Enumeration e = partition_map.elements(); e.hasMoreElements();) {
            partition = (Partition) e.nextElement();
            if (partition.getName().equals(name)) {
                return partition;
            }
        }
        return null;
    }

    /**
     * Finds the partition that matches the given extent, if any.
     * @param extent The extent to compare to.
     * @return The first matching partition, or null if none.
     */
    public Partition getPartition(Extent extent) {
        Partition partition = null;
        for (Enumeration e = partition_map.elements(); e.hasMoreElements();) {
            partition = (Partition) e.nextElement();
            if (partition.matchesExtent(extent)) {
                return partition;
            }
        }
        return null;
    }
    
    /**
     * Find the ith partition in the partition list.
     * @param i Index number.
     * @return The partition, or null if out of range.
     */
    public Partition getPartition(int i) {
        if ( i >= partition_map.size() ) {
          return null;
        }
        return (Partition) partition_map.elementAt( i );
    }

    /**
     * Adds the given partition as a XenoPartition.
     * @param p The partition to add.
     */
    void addXenoPartition(Partition p) {
        for (Enumeration e = partition_map.elements(); e.hasMoreElements();) {
            Partition partition = (Partition) e.nextElement();
            if (partition.identical(p)) {
                partition.makeXeno();
            }
        }
    }

    /**
     * Dump the XenoPartition list as XML.
     * @param out Writer to dump to.
     */
    void dumpAsXML(PrintWriter out) {
        out.println("<partitions>");
        for (Enumeration e = partition_map.elements(); e.hasMoreElements();) {
            Partition partition = (Partition) e.nextElement();
            if (partition.isXeno()) {
                partition.dumpAsXML(out);
            }
        }

        out.println("</partitions>");

        return;
    }

    /**
     * @return The number of partitions. 
     */
    public int getPartitionCount() {
        return partition_map.size();
    }

    /**
     * Get an iterator over all the partitions.
     * @return An iterator over Partition objects.
     */
    public Iterator iterator() {
        return partition_map.iterator();
    }
}
