package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVbdDelete;
import org.xenoserver.control.Defaults;

public class ParseVbdDelete extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        int domain_id = getIntParameter(args, 'n', 0);
        int vbd_num = getIntParameter(args, 'v', -1);

        if (domain_id == 0) {
            throw new ParseFailedException("Expected -n<domain_id>");
        }
        if (vbd_num == -1) {
            throw new ParseFailedException("Expected -v<vbd_num>");
        }
        loadState();
        String output = new CommandVbdDelete(domain_id, vbd_num).execute();
        if (output != null) {
            System.out.println(output);
        }
        saveState();
    }

    public String getName() {
        return "delete";
    }

    public String getUsage() {
        return "-n<domain> -v<vbd>";
    }

    public String getHelpText() {
        return "Deletes the specified virtual block device from the specified domain.";
    }

}
