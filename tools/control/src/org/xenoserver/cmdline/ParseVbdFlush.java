package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVbdFlush;
import org.xenoserver.control.Defaults;

public class ParseVbdFlush extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        loadState();
        String output = new CommandVbdFlush().execute();
        if (output != null) {
            System.out.println(output);
        }
        saveState();
    }

    public String getName() {
        return "flush";
    }

    public String getUsage() {
        return "";
    }

    public String getHelpText() {
        return "Delete all virtual block devices";
    }
}
