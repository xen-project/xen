package org.xenoserver.control;

/**
 * Thrown to indicate that a command failed to execute.
 */
public class CommandFailedException extends Exception {
    /**
     * Construct an exception with a message.
     * @param message Message to use.
     */
    public CommandFailedException(String message) {
        super(message);
    }

    /**
     * Construct an exception with a message and cause.
     * @param message Message to use.
     * @param cause Throwable cause.
     */
    public CommandFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Construct an exception for an XI command failure.
     * @param message Message to use
     * @param cmd_array Command array used to invoke xi command
     * @return Suitable exception.
     */
    public static CommandFailedException xiCommandFailed(
        String message,
        String cmd_array[]) {
        StringBuffer sb = new StringBuffer();
        int i;
        sb.append(message + " using: ");
        for (i = 0; i < cmd_array.length; i++) {
            sb.append(cmd_array[i] + " ");
        }
        return new CommandFailedException(sb.toString());
    }
}
