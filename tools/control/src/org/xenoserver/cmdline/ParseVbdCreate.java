package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVbdCreate;
import org.xenoserver.control.CommandVbdCreatePhysical;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Mode;
import org.xenoserver.control.Partition;
import org.xenoserver.control.PartitionManager;
import org.xenoserver.control.VirtualDisk;
import org.xenoserver.control.VirtualDiskManager;

public class ParseVbdCreate extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        String vd_key = getStringParameter(args, 'k', "");
        String partition_name = getStringParameter(args, 'p', "");
        int domain_id = getIntParameter(args, 'n', 0);
        int vbd_num = getIntParameter(args, 'v', -1);
        boolean write = getFlagParameter(args, 'w');

        if (vd_key.equals("") && partition_name.equals("")) {
            throw new ParseFailedException("Expected -k<key> or -p<partition>");
        }
        if (domain_id == 0) {
            throw new ParseFailedException("Expected -n<domain_id>");
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
            Partition p = PartitionManager.IT.getPartition(partition_name);
            if ( p == null ) {
                throw new CommandFailedException("No partition " + partition_name + " exists" );
            }
            
            output = new CommandVbdCreatePhysical( p, domain_id, vbd_num, mode ).execute();
        } else {
            VirtualDisk vd = VirtualDiskManager.IT.getVirtualDisk(vd_key);
            if (vd == null) {
                throw new CommandFailedException(
                    "No virtual disk with key " + vd_key);
            }

            output =
                new CommandVbdCreate(vd, domain_id, vbd_num, mode).execute();
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
        return "-n<domain_id> {-k<key>|-p<partition} -v<vbd_num> [-w]";
    }

    public String getHelpText() {
        return "Create a new virtual block device binding the virtual disk with\n"
            + "the specified key to the domain and VBD number given. Add -w to\n"
            + "allow read-write access.";
    }

}
