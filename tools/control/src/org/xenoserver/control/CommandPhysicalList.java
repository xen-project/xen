package org.xenoserver.control;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Lists details of all extents the given domain has access to.
 * After execute() has been called, call extents() to get the map of extents
 * to modes.
 */
public class CommandPhysicalList extends Command {
    /** Domain to list details for */
    private int domain_id;
    /** Defaults instance to use. */
    private Defaults d;
    /** Map of extents to access modes */
    private Map map = new HashMap();

    /**
     * Constructor for CommandDomainList.
     * @param d Defaults object to use.
     * @param domain_id Domain ID to query for
     */
    public CommandPhysicalList(Defaults d, int domain_id) {
        this.d = d;
        this.domain_id = domain_id;
    }

    /**
     * Retrieves the list of extents.
     * @return null, call extents() to get the list.
     * @throws CommandFailedException if the list could not be retrieved.
     */
    public String execute() throws CommandFailedException {
        Runtime r = Runtime.getRuntime();
        String outline;
        BufferedReader in;
        String output = null;

        try {
            Process start_p;
            String start_cmdarray[] = new String[2];
            int start_rc;
            start_cmdarray[0] = d.xiToolsDir + "xi_phys_probe";
            start_cmdarray[1] = Integer.toString(domain_id);

            if (Settings.TEST) {
                output = reportCommand(start_cmdarray);
            } else {
                start_p = r.exec(start_cmdarray);
                start_rc = start_p.waitFor();
                if (start_rc != 0) {
                    throw CommandFailedException.xiCommandFailed(
                        "Could not get extent list",
                        start_cmdarray);
                }

                in =
                    new BufferedReader(
                        new InputStreamReader(start_p.getInputStream()));

                outline = in.readLine();
                while (outline != null) {
                    int disk = -1;
                    int partition_no = -1;
                    long offset = -1;
                    long size = -1;

                    StringTokenizer st = new StringTokenizer(outline);
                    if (st.hasMoreTokens()) {
                        disk = Integer.parseInt(st.nextToken(), 16);
                    }
                    if (st.hasMoreTokens()) {
                        partition_no = Integer.parseInt(st.nextToken(), 16);
                    }
                    if (st.hasMoreTokens()) {
                        offset = Long.parseLong(st.nextToken(), 16);
                    }
                    if (st.hasMoreTokens()) {
                        size = Long.parseLong(st.nextToken(), 16);
                    }
                    if (st.hasMoreTokens()) {
                        String mode = st.nextToken();
                        Extent extent = new Extent(disk, offset, size, partition_no);
                        if (mode.equals("rw")) {
                            map.put(extent, Mode.READ_WRITE);
                        } else if (mode.equals("r")) {
                            map.put(extent, Mode.READ_ONLY);
                        } else {
                            throw new CommandFailedException(
                                "Could not parse access mode " + mode);
                        }
                    }

                    outline = in.readLine();
                }

            }
        } catch (CommandFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailedException(
                "Could not get extent list(" + e + ")",
                e);
        }

        return output;
    }

    /**
     * @return Map of extents to access modes.
     */
    public Map extents() {
        return map;
    }
}
