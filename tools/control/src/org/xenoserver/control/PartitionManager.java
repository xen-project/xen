/*
 * PartitionManager.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;

/**
 * PartitionManager manages the partitions on the machine. It is a Singleton
 * which automatically initialises itself on first class reference.
 */
public class
PartitionManager
{
  static final String proc_template =
    "major minor  #blocks  start_sect   nr_sects name";
    
  public static final PartitionManager it = new PartitionManager(Settings.PARTITIONS_FILE);
    
  Vector partition_map;

  /*
   * Initialize partition manager with source file.
   * Normally we read from /proc/partitions, but we can
   * specify an alternative file for debugging
   */
  private PartitionManager (String filename)
  {
    String str;
    BufferedReader in;

    partition_map = new Vector(100,10);

    try
    {
      in = new BufferedReader(new FileReader(filename));

      str = in.readLine();                                  /* skip headings */
      if (str.length() < proc_template.length() ||
	  !str.substring(0, proc_template.length()).equals(proc_template))
      {
	System.err.println ("Error: Incorrect /proc/partitions.");
	System.err.println ("       Is this Xeno?");
	System.exit (1);
      }

      str = in.readLine();                                /* skip blank line */

      str = in.readLine();
      while (str != null)
      {
	Partition partition = new Partition();

	partition.major = Integer.parseInt(str.substring(0,5).trim());
	partition.minor = Integer.parseInt(str.substring(5,10).trim());
	partition.blocks = Integer.parseInt(str.substring(10,21).trim());
	partition.start_sect = Integer.parseInt(str.substring(21,32).trim());
	partition.nr_sects = Integer.parseInt(str.substring(32,43).trim());
	partition.name = str.substring(43).trim();
	partition.xeno = false;

	partition_map.add(partition);
	str = in.readLine();
      }
    }
    catch (IOException io)
    {
      System.err.println ("PartitionManager: error reading partition file [" 
			  + filename + "]");
      System.err.println (io);
    }
  }

  public Partition
  get_partition (String name)
  {
    Partition partition = null;
    for (Enumeration e = partition_map.elements() ; e.hasMoreElements() ;) 
    {
      partition = (Partition) e.nextElement();
      if (partition.name.equals(name))
      {
  return partition;
      }
    }
    return null;
  }

  /**
   * Finds the partition that matches the given extent, if any.
   * @param extent The extent to compare to.
   * @return The first matching partition, or null if none.
   */
  public Partition
  get_partition (Extent extent)
  {
    Partition partition = null;
    for (Enumeration e = partition_map.elements() ; e.hasMoreElements() ;) 
    {
      partition = (Partition) e.nextElement();
      if (partition.matchesExtent(extent))
      {
  return partition;
      }
    }
    return null;
  }

  Partition
  get_partition (int index)
  {
    return (Partition) partition_map.get(index);
  }

  void
  add_xeno_partition (Partition p)
  {
    for (Enumeration e = partition_map.elements() ; e.hasMoreElements() ;) 
    {
      Partition partition = (Partition) e.nextElement();
      if (partition.equals(p))
      {
	partition.xeno = true;
      }
    }
  }

  /*
   * dump the xeno partition list as xml
   */
  void
  dump_xml (PrintWriter out)
  {
    out.println("<partitions>");
    for (Enumeration e = partition_map.elements() ; e.hasMoreElements() ;) 
    {
      Partition partition = (Partition) e.nextElement();
      if (partition.xeno == true)
      {
	partition.dump_xml(out);
      }
    }

    out.println("</partitions>");

    return;
  }

  /**
   * get the number of partitions 
   */

  int
  getPartitionCount ()
  {
    return partition_map.size();
  }

  /**
   * get the details about a particular partition
   *
   */
  Partition
  getPartition (int index)
  {
    Partition partition = (Partition) partition_map.get(index);
    return partition;
  }
 
  /**
   * Get an iterator over all the partitions.
   * @return An iterator over Partition objects.
   */
  public Iterator iterator()
  {
    return partition_map.iterator();
  }
}
