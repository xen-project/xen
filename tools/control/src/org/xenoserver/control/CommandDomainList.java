package org.xenoserver.control;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.StringTokenizer;
import java.util.Vector;

/**
 * Lists details of all domains. After execute() has been called, call
 * domains() to get the array of domains.
 */
public class CommandDomainList extends Command {
  private Defaults d;
  private Domain[] array;

  /**
   * Constructor for CommandDomainList.
   * @param d Defaults object to use.
   */
  public CommandDomainList(Defaults d) {
    this.d = d;
  }

  /**
   * Retrieves the list of domains.
   * @return null, call domains() to get the list.
   */
  public String execute() throws CommandFailedException {
    Runtime r = Runtime.getRuntime();
    Vector v = new Vector();
    String outline;
    BufferedReader in;
    String output = null;

    try {
      Process start_p;
      String start_cmdarray[] = new String[1];
      int start_rc;
      start_cmdarray[0] = d.XIToolsDir + "xi_list";

      if (Settings.TEST) {
        output = reportCommand(start_cmdarray);
      } else {
        start_p = r.exec(start_cmdarray);
        start_rc = start_p.waitFor();
        if (start_rc != 0) {
          throw CommandFailedException.XICommandFailed("Could not get domain list", start_cmdarray);
        }

        in =
          new BufferedReader(new InputStreamReader(start_p.getInputStream()));

        outline = in.readLine();
        while (outline != null) {
          Domain domain = new Domain();

          StringTokenizer st = new StringTokenizer(outline);
          if (st.hasMoreTokens()) {
            domain.id = Integer.parseInt(st.nextToken());
          }
          if (st.hasMoreTokens()) {
            domain.processor = Integer.parseInt(st.nextToken());
          }
          if (st.hasMoreTokens()) {
            if (st.nextToken().equals("1")) {
              domain.cpu = true;
            } else {
              domain.cpu = false;
            }
          }
          if (st.hasMoreTokens()) {
            domain.nstate = Integer.parseInt(st.nextToken());
          }
          if (st.hasMoreTokens()) {
            domain.state = st.nextToken().toLowerCase();
          }
          if (st.hasMoreTokens()) {
            domain.mcu = Integer.parseInt(st.nextToken());
          }
          if (st.hasMoreTokens()) {
            domain.pages = Integer.parseInt(st.nextToken());
          }
          if (st.hasMoreTokens()) {
            domain.name = st.nextToken();
          }

          v.add(domain);

          outline = in.readLine();
        }

      }
    } catch (CommandFailedException e) {
      throw e;
    } catch (Exception e) {
      throw new CommandFailedException("Could not get domain list(" + e + ")", e);
    }

    array = new Domain[v.size()];
    v.toArray(array);
    return output;
  }
  
  public Domain[] domains() {
    return array;
  }
}
