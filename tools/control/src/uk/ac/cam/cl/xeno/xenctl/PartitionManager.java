/*
 * PartitionManager.java
 * 03.03.26 aho creation
 */

package uk.ac.cam.cl.xeno.xenctl;

import java.io.*;
import java.util.Vector;
import java.util.Enumeration;

public class
PartitionManager
{
  Vector partition_map;

  static String proc_template =
    "major minor  #blocks  start_sect   nr_sects name";

  /*
   * Initialize partition manager with source file.
   * Normally we read from /proc/partitions, but we can
   * specify an alternative file for debugging
   */
  PartitionManager (String filename)
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

  Partition
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
      if (partition.identical(p))
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
    int loop;

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

  /*
   * dump the partition map as a string
   * mark: mark the current xeno partitions in the partition map
   */
  String
  dump (boolean mark)
  {
    int loop, idx;
    StringBuffer sb = new StringBuffer();
    Partition partition;

    for (idx = 0; idx < partition_map.size(); idx++)
    {
      partition = (Partition) partition_map.get(idx);

      if (idx == 0)
      {
	sb.append(" idx " + partition.dump(true) + "\n");
      }
      if (partition.xeno)
      {
	sb.append("[ ");
      }
      else
      {
	sb.append("  ");
      }
      sb.append(Library.format(idx,2,0) + " " + partition.dump(false));
      if (partition.xeno)
      {
	sb.append("]\n");
      }
      else
      {
	sb.append("\n");
      }
    }

    return sb.toString();
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

}
