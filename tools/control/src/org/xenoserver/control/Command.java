package org.xenoserver.control;

/**
 * Subclasses of Command are responsible for applying changes to domain
 * and virtual disk settings.
 */
public abstract class Command {
  /**
   * Subclasses should define an execute method which will apply the
   * relevant change, if possible.
   * 
   * @return The results of executing the command, if successful, or null if
   *         the command does not need to return results.
   * @throws CommandFailedException if the command could not be completed.
   */
  public abstract String execute() throws CommandFailedException;

  protected String reportCommand (String cmd_array[])
  {
    StringBuffer sb = new StringBuffer();
    int i;
    for (i = 0; i < cmd_array.length; i ++) {
      sb.append (cmd_array[i] + " ");
    }
    return sb.toString();
  }
}
