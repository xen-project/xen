package org.xenoserver.control;

/**
 * Destroys a domain.
 */
public class CommandDestroy extends Command {
  private Defaults d;
  private int domain_id;
  private boolean force;

  /**
   * Constructor for CommandDestroy.
   * 
   * @param d Defaults object to use.
   * @param domain_id Domain ID number to destroy.
   * @param force Force destruction.
   */
  public CommandDestroy(Defaults d, int domain_id, boolean force) {
    this.d = d;
    this.domain_id = domain_id;
    this.force = force;
  }

  public String execute() throws CommandFailedException {
    Runtime r = Runtime.getRuntime();
    String output = null;

    try {
      Process destroy_p;
      String destroy_cmdarray[] = force ? new String[3] : new String[2];
      int destroy_rc;
      int idx = 0;
      destroy_cmdarray[idx++] = d.XIToolsDir + "xi_destroy";
      if (force) {
        destroy_cmdarray[idx++] = "-f";
      }
      destroy_cmdarray[idx++] = "" + domain_id;

      if (Settings.TEST) {
        output = reportCommand(destroy_cmdarray);
      } else {
        destroy_p = r.exec(destroy_cmdarray);
        destroy_rc = destroy_p.waitFor();

        if (destroy_rc != 0) {
          throw CommandFailedException.XICommandFailed("Could not destroy domain", destroy_cmdarray);
        }
        output = "Destroyed domain " + domain_id;
      }
    } catch (CommandFailedException e) {
      throw e;
    } catch (Exception e) {
      throw new CommandFailedException("Could not destroy domain (" + e + ")", e);
    }

    return output;
  }
}
