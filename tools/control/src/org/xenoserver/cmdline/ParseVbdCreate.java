package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVbdCreate;
import org.xenoserver.control.CommandVbdCreatePhysical;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Mode;

public class ParseVbdCreate extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        String vd_key = getStringParameter(args, 'k', "");
        String partition_name = getStringParameter(args, 'p', "");
        int domain_id = getIntParameter(args, 'n', d.domainNumber);
        int vbd_num = getIntParameter(args, 'v', -1);
        boolean write = getFlagParameter(args, 'w');
	int subst = getIntParameter(args, 'x', -1);

        if (vd_key.equals("") && partition_name.equals("")) {
            throw new ParseFailedException("Expected -k<key> or -p<partition>");
        }
        if (vbd_num == -1) {
            throw new ParseFailedException("Expected -v<vbd_num>");
        }

        Mode mode;
        if (write) {
            mode = Mode.READ_WRITE;
        } else {
            mode = Mode.READ_ONLY;
        }

        loadState();
        String output;
        if (vd_key.equals("")) {
            output = new CommandVbdCreatePhysical(d,  partition_name, domain_id, vbd_num, mode, subst ).execute();
        } else {
            output =
                new CommandVbdCreate(vd_key, domain_id, vbd_num, mode).execute();
        }
        if (output != null) {
            System.out.println(output);
        }
        saveState();
    }

    public String getName() {
        return "create";
    }

    public String getUsage() {
        return "{-k<key>|-p<partition} -v<vbd_num> [-n<domain_id>] [-w] [-x<subst>]";
    }

    public String getHelpText() {
        return "Create a new virtual block device binding the virtual disk with\n"
            + "the specified key to the domain and VBD number given. Add -w to\n"
            + "allow read-write access.";
    }

}
