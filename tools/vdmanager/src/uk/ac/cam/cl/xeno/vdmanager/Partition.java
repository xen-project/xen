/*
 * PartitionManager.java
 * 03.03.26 aho creation
 */

package uk.ac.cam.cl.xeno.vdmanager;

import java.io.*;

public class
Partition
{
  int major;
  int minor;
  long blocks;
  long start_sect;
  long nr_sects;
  String name;

  boolean 
  identical (Partition p)
  {
    return (major == p.major &&
	    minor == p.minor &&
	    blocks == p.blocks &&
	    start_sect == p.start_sect &&
	    nr_sects == p.nr_sects &&
	    name.equals(p.name));
  }

  Partition
  duplicate ()
  {
    Partition p = new Partition();

    p.major = major;
    p.minor = minor;
    p.blocks = blocks;
    p.start_sect = start_sect;
    p.nr_sects = nr_sects;
    p.name = name;

    return p;
  }

  String 
  dump (boolean title)
  {
    if (title)
    {
      return ("maj:min " + 
	      "    blocks " +
	      "start sect " +
	      " num sects " +
	      "name");
    }
    else
    {
      return (Library.format(major,3,0) + ":" + 
	      Library.format(minor,3,1) + " " +
	      Library.format(blocks,10,0) + " " +
	      Library.format(start_sect,10,0) + " " +
	      Library.format(nr_sects,10,0) + " " +
	      Library.format(name,7,1));
    }
  }

  void
  dump_xml(PrintWriter out)
  {
    out.println ("  <partition>\n" +
		 "    <major>" + major + "</major>\n" +
		 "    <minor>" + minor + "</minor>\n" +
		 "    <blocks>" + blocks + "</blocks>\n" +
		 "    <start_sect>" + start_sect + "</start_sect>\n" +
		 "    <nr_sects>" + nr_sects + "</nr_sects>\n" +
		 "    <name>" + name + "</name>\n" +
		 "  </partition>");
  }
}
