package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Library;
import org.xenoserver.control.VirtualBlockDevice;
import org.xenoserver.control.VirtualDiskManager;

public class ParseVbdShow extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        loadState();
        Iterator i = VirtualDiskManager.IT.getVirtualBlockDevices();
        System.out.println("key         dom vbd mode");
        while (i.hasNext()) {
            VirtualBlockDevice vbd = (VirtualBlockDevice) i.next();
            System.out.println( vbd.getVirtualDisk().getKey()
                    + "  "
                    + Library.format(vbd.getDomain(), 3, false)
                    + " "
                    + Library.format(vbd.getVbdNum(), 3, false)
                    + " "
                    + vbd.getMode().toString());
        }
    }

    public String getName() {
        return "show";
    }

    public String getUsage() {
        return "";
    }

    public String getHelpText() {
        return "Show details of all mapped virtual block devices.";
    }
}
