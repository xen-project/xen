/*
 * Mode.java
 * 03.03.27 aho creation
 *
 * until we have jdk1.5, we're left with this mess...
 */

package org.xenoserver.control;

/**
 * Enumeration to represent an access mode.
 */
public class Mode {
    /** name of this mode */
    private final String name;

    /**
     * Construct a mode
     * @param name Name to use.
     */
    private Mode(String name) {
        this.name = name;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return name;
    }

    /** Single read-only mode instance. */
    public static final Mode READ_ONLY = new Mode("ro");
    /** Single read-write mode instance. */
    public static final Mode READ_WRITE = new Mode("rw");
}
