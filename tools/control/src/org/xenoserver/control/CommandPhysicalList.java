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
  private int domain_id;
  private Defaults d;
  private Map map = new HashMap();

  /**
   * Constructor for CommandDomainList.
   * @param d Defaults object to use.
   */
  public CommandPhysicalList(Defaults d, int domain_id) {
    this.d = d;
    this.domain_id = domain_id;
  }

  /**
   * Retrieves the list of extents.
   * @return null, call extents() to get the list.
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
      start_cmdarray[0] = d.XIToolsDir + "xi_phys_probe";
      start_cmdarray[1] = Integer.toString( domain_id );

      if (Settings.TEST) {
        output = reportCommand(start_cmdarray);
      } else {
        start_p = r.exec(start_cmdarray);
        start_rc = start_p.waitFor();
        if (start_rc != 0) {
          throw CommandFailedException.XICommandFailed("Could not get extent list", start_cmdarray);
        }

        in =
          new BufferedReader(new InputStreamReader(start_p.getInputStream()));

        outline = in.readLine();
        while (outline != null) {
          Extent extent = new Extent();

          StringTokenizer st = new StringTokenizer(outline);
          if (st.hasMoreTokens()) {
            extent.disk = Short.parseShort(st.nextToken(),16);
          }
          if (st.hasMoreTokens()) {
            extent.offset = Long.parseLong(st.nextToken(),16);
          }
          if (st.hasMoreTokens()) {
            extent.size = Long.parseLong(st.nextToken(),16);
          }
          if (st.hasMoreTokens()) {
            String mode = st.nextToken();
            if ( mode.equals( "rw" ) )
              map.put( extent, Mode.READ_WRITE );
            else if ( mode.equals ( "r" ) )
              map.put( extent, Mode.READ_ONLY );
            else
              throw new CommandFailedException("Could not parse access mode " + mode);
          }

          outline = in.readLine();
        }

      }
    } catch (CommandFailedException e) {
      throw e;
    } catch (Exception e) {
      throw new CommandFailedException("Could not get extent list(" + e + ")", e);
    }

    return output;
  }
  
  public Map extents() {
    return map;
  }
}
