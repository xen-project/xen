package org.xenoserver.cmdline;

/**
 * Thrown when a command line could not be parsed.
 */
public class ParseFailedException extends Exception {
    public ParseFailedException(String message) {
        super(message);
    }

    public ParseFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
