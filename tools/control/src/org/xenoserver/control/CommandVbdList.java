package org.xenoserver.control;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.StringTokenizer;
import java.util.Vector;

public class CommandVbdList extends Command {
    /** Array of virtual block devices returned */
    private VirtualBlockDevice[] array;

    public String execute() throws CommandFailedException {
        Vector v = new Vector();
        BufferedReader in;
        String line;

        try {
            in = new BufferedReader(new FileReader("/proc/xeno/dom0/vhd"));
            line = in.readLine();
            while (line != null) {
                int domain = -1;
                int vbdnum = -1;
                String key = "";
                Mode mode = Mode.READ_ONLY;

                StringTokenizer st = new StringTokenizer(line);
                if (st.hasMoreTokens()) {
                    domain = Integer.parseInt(st.nextToken());
                }
                if (st.hasMoreTokens()) {
                    vbdnum = Integer.parseInt(st.nextToken());
                }
                if (st.hasMoreTokens()) {
                    key = st.nextToken();
                }
                if (st.hasMoreTokens()) {
                    if (Integer.parseInt(st.nextToken()) == 2) {
                        mode = Mode.READ_WRITE;
                    }
                }

                VirtualDisk vd = VirtualDiskManager.IT.getVirtualDisk(key);
                if (vd == null) {
                    throw new CommandFailedException(
                        "Key " + key + " has no matching virtual disk");
                }
                VirtualBlockDevice vbd =
                    new VirtualBlockDevice(vd, domain, vbdnum, mode);
                v.add(vbd);

                line = in.readLine();
            }
        } catch (IOException e) {
            throw new CommandFailedException("Could not read VBD file", e);
        }

        array = new VirtualBlockDevice[v.size()];
        v.toArray(array);
        return null;
    }
    
    public VirtualBlockDevice[] vbds() {
        return array;
    }
}
