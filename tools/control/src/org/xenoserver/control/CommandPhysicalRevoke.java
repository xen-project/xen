package org.xenoserver.control;

public class CommandPhysicalRevoke extends Command {
  private Defaults d;
  private int domain_id;
  private Extent extent;

  /**
   * Constructor for CommandPhysicalRevoke.
   * @param d Defaults object to use.
   * @param domain_id Domain to revoke access from.
   * @param extent Extent to revoke access from.
   */
  public CommandPhysicalRevoke(
    Defaults d,
    int domain_id,
    Extent extent) {
    this.d = d;
    this.domain_id = domain_id;
    this.extent = extent;
  }

  public String execute() throws CommandFailedException {
    Runtime r = Runtime.getRuntime();
    String output = null;

    try {
      Process start_p;
      String start_cmdarray[] = new String[5];
      int start_rc;
      start_cmdarray[0] = d.XIToolsDir + "xi_phys_revoke";
      start_cmdarray[1] = Integer.toString( domain_id );
      start_cmdarray[2] = Integer.toString( extent.getDisk() );
      start_cmdarray[3] = Long.toString( extent.getOffset() );
      start_cmdarray[4] = Long.toString( extent.getSize() );

      if (Settings.TEST) {
        output = reportCommand(start_cmdarray);
      } else {
        start_p = r.exec(start_cmdarray);
        start_rc = start_p.waitFor();
        if (start_rc != 0) {
          throw CommandFailedException.XICommandFailed("Could not revoke physical access", start_cmdarray);
        }
        output = "Revoked physical access from domain " + domain_id;
      }
    } catch (CommandFailedException e) {
      throw e;
    } catch (Exception e) {
      throw new CommandFailedException("Could not revoke physical access (" + e + ")", e);
    }

    return output;
  }

}
