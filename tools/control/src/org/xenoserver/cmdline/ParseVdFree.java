package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Extent;
import org.xenoserver.control.Library;
import org.xenoserver.control.Settings;
import org.xenoserver.control.VirtualDisk;
import org.xenoserver.control.VirtualDiskManager;

public class ParseVdFree extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        boolean verbose = getFlagParameter(args, 'v');

        loadState();
        VirtualDisk free = VirtualDiskManager.IT.getFreeDisk();
        System.out.println(
            "Free disk has "
                + free.getExtentCount()
                + " extents totalling "
                + Library.formatSize(
                    free.getSize() * Settings.SECTOR_SIZE,
                    8,
                    true));
        if (verbose) {
            Iterator i = free.extents();
            System.out.println("  disk       offset         size");
            while (i.hasNext()) {
                Extent e = (Extent) i.next();
                System.out.println(
                    Library.format(e.getDisk(), 6, false)
                        + " "
                        + Library.format(e.getOffset(), 12, false)
                        + " "
                        + Library.format(e.getSize(), 12, false));
            }
        }
    }

    public String getName() {
        return "free";
    }

    public String getUsage() {
        return "[-v]";
    }

    public String getHelpText() {
        return "Show free space allocated to virtual disk manager. -v enables verbose output.";
    }
}
