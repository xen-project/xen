package org.xenoserver.control;

public class CommandPhysicalGrant extends Command {
  private Defaults d;
  private int domain_id;
  private Extent extent;
  private Mode mode;

  /**
   * Constructor for CommandPhysicalGrant.
   * @param d Defaults object to use.
   * @param domain_id Domain to grant access for.
   * @param extent Extent to grant access to.
   * @param mode Access mode to grant.
   */
  public CommandPhysicalGrant(
    Defaults d,
    int domain_id,
    Extent extent,
    Mode mode) {
    this.d = d;
    this.domain_id = domain_id;
    this.extent = extent;
    this.mode = mode;
  }

  public String execute() throws CommandFailedException {
    Runtime r = Runtime.getRuntime();
    String output = null;

    try {
      Process start_p;
      String start_cmdarray[] = new String[6];
      int start_rc;
      start_cmdarray[0] = d.XIToolsDir + "xi_phys_grant";
      if ( mode == Mode.READ_WRITE )
        start_cmdarray[1] = "rw";
      else if ( mode == Mode.READ_ONLY )
        start_cmdarray[1] = "ro";
      else
        throw new CommandFailedException( "Unknown access mode '" + mode + "'" );
      start_cmdarray[2] = Integer.toString( domain_id );
      start_cmdarray[3] = Short.toString( extent.getDisk() );
      start_cmdarray[4] = Long.toString( extent.getOffset() );
      start_cmdarray[5] = Long.toString( extent.getSize() );

      if (Settings.TEST) {
        output = reportCommand(start_cmdarray);
      } else {
        start_p = r.exec(start_cmdarray);
        start_rc = start_p.waitFor();
        if (start_rc != 0) {
          throw CommandFailedException.XICommandFailed("Could not grant physical access", start_cmdarray);
        }
        output = "Granted physical access to domain " + domain_id;
      }
    } catch (CommandFailedException e) {
      throw e;
    } catch (Exception e) {
      throw new CommandFailedException("Could not grant physical access (" + e + ")", e);
    }

    return output;
  }

}
