/*
 * Mode.java
 * 03.03.27 aho creation
 */

package uk.ac.cam.cl.xeno.vdmanager;

public class 
Mode 
{
  private final String name;

  private Mode(String name) { this.name = name; }

  public String toString()  { return name; }

  public static final Mode READ_ONLY  = new Mode("ro");
  public static final Mode READ_WRITE = new Mode("rw");
}

