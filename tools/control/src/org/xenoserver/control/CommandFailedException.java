package org.xenoserver.control;

/**
 * Thrown to indicate that a command failed to execute.
 */
public class CommandFailedException extends Exception {
  public CommandFailedException() {
    super();
  }

  public CommandFailedException(String message) {
    super(message);
  }

  public CommandFailedException(String message, Throwable cause) {
    super(message, cause);
  }

  public CommandFailedException(Throwable cause) {
    super(cause);
  }
  
  public static CommandFailedException XICommandFailed(String message, String cmd_array[]) {
    StringBuffer sb = new StringBuffer();
    int i;
    sb.append (message + " using: ");
    for (i = 0; i < cmd_array.length; i ++) {
      sb.append (cmd_array[i] + " ");
    }
    return new CommandFailedException( sb.toString() );    
  }
}
