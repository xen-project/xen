/*
 * Mode.java
 * 03.03.27 aho creation
 *
 * until we have jdk1.5, we're left with this mess...
 */

package org.xenoserver.control;

public class 
Mode 
{
  private final String name;

  private Mode(String name) { this.name = name; }

  public String toString()  { return name; }

  public static final Mode READ_ONLY  = new Mode("ro");
  public static final Mode READ_WRITE = new Mode("rw");
}

