package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Library;
import org.xenoserver.control.Partition;
import org.xenoserver.control.PartitionManager;

public class ParsePartitionsList extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        loadState();
        Iterator i = PartitionManager.IT.iterator();
        int idx = 1;
        System.out.println(
            "     maj:min "
                + "    blocks "
                + "start sect "
                + " num sects "
                + "name");
        while (i.hasNext()) {
            Partition p = (Partition) i.next();

            if (p.isXeno()) {
                System.out.print("[ ");
            } else {
                System.out.print("  ");
            }
            System.out.print(Library.format(idx++, 2, false) + " ");
            System.out.print(
                Library.format(p.getMajor(), 3, false)
                    + ":"
                    + Library.format(p.getMinor(), 3, true)
                    + " "
                    + Library.format(p.getBlocks(), 10, false)
                    + " "
                    + Library.format(p.getStartSect(), 10, false)
                    + " "
                    + Library.format(p.getNumSects(), 10, false)
                    + " "
                    + Library.format(p.getName(), 7, true));
            if (p.isXeno()) {
                System.out.println("]");
            } else {
                System.out.println();
            }
        }
    }

    public String getName() {
        return "list";
    }

    public String getUsage() {
        return "";
    }

    public String getHelpText() {
        return "List physical partition information. Partitions surrounded by [] are XenoPartitions.";
    }

}
