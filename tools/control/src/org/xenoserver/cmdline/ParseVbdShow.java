package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVbdList;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Library;
import org.xenoserver.control.VirtualBlockDevice;

public class ParseVbdShow extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        loadState();
        CommandVbdList list = new CommandVbdList();
        list.execute();
        VirtualBlockDevice[] vbds = list.vbds();
        System.out.println("key         dom vbd mode");
        for (int i=0; i<vbds.length; i++) {
            System.out.println( vbds[i].getVirtualDisk().getKey()
                    + "  "
                    + Library.format(vbds[i].getDomain(), 3, false)
                    + " "
                    + Library.format(vbds[i].getVbdNum(), 3, false)
                    + " "
                    + vbds[i].getMode().toString());
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
