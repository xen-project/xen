/*
 * VirtualDisk.java
 * 03.03.26 aho creation
 */

package uk.ac.cam.cl.xeno.xenctl;

import java.util.Date;
import java.util.Vector;
import java.lang.Math;
import java.io.PrintWriter;

public class
VirtualDisk
{
  String name;
  String key;
  Date   expiry;
  Vector extents;

  VirtualDisk (String name, Date expiry, String key)
  {
    this.name = name;
    this.key = key;
    this.expiry = expiry;
    extents = new Vector();
  }

  VirtualDisk (String name)
  {
    this (name, null, null);
    this.key = generate_key();
    extents = new Vector();

    return;
  }

  VirtualDisk (String name, Date expiry)
  {
    this(name, expiry, null);
    this.key = generate_key();
  }

  /*
   * generate a unique key for this virtual disk.
   * for now, just generate a 10 digit number
   */
  String
  generate_key ()
  {
    return Long.toString(1000000000l + (long)(Math.random() * 8999999999l));
  }

  String
  get_key ()
  {
    return key;
  }

  Date
  get_expiry ()
  {
    return expiry;
  }
  
  void
  set_expiry (Date expiry)
  {
    this.expiry = expiry;
  }

  public void
  add_extent (Extent extent)
  {
    extents.add(extent);
  }

  public Extent
  remove_extent ()
  {
    Extent e;

    if (extents.size() > 0)
    {
      e = (Extent) extents.remove(0);
    }
    else
    {
      e = null;
    }

    return e;
  }

  String
  dump (boolean details, boolean title)
  {
    StringBuffer sb = new StringBuffer();
    int loop;

    if (details)
    {
      if (title)
      {
	sb.append("  name: " + name   + "\n");
	sb.append("   key: " + key    + "\n");
	sb.append("expiry: " + expiry + "\n");
	sb.append("\n");
      }
      sb.append("   idx  disk    offset      size \n");
      for (loop = 0; loop < extents.size(); loop++)
      {
	Extent e = (Extent) extents.get(loop);
	sb.append("  " + 
		  Library.format(loop,3,0) + " " +
		  Library.format(e.disk,6,0) +
		  Library.format(e.offset,10,0) +
		  Library.format(e.size,10,0) + "\n");
      }
    }
    else
    {
      if (title)
      {
	sb.append("  key         expiry                        name\n");
      }
      else
      {
	sb.append("  " + key + "  " + expiry.toString() + "  " + name + "\n");
      }
    }

    return sb.toString();
  }

  String
  dump_xen ()
  {
    StringBuffer sb = new StringBuffer();

    sb.append("extents:" + extents.size() + " ");
    for (int loop = 0; loop < extents.size(); loop++)
    {
      Extent e = (Extent) extents.get(loop);
      sb.append("(disk:" + e.disk + " " +
		"offset:" + e.offset + " " +
		"size:" + e.size + ")");
    }
    return sb.toString();
  }

  String
  dump_xen (VirtualBlockDevice vbd)
  {
    StringBuffer sb = new StringBuffer();

    sb.append("domain:" + vbd.domain + " " +
	      vbd.mode.toString() + " " +
	      "segment:" + vbd.vbdnum + " " +
	      "extents:" + extents.size() + " ");
    for (int loop = 0; loop < extents.size(); loop++)
    {
      Extent e = (Extent) extents.get(loop);
      sb.append("(disk:" + e.disk + " " +
		"offset:" + e.offset + " " +
		"size:" + e.size + ")");
    }
    return sb.toString();
  }

  void
  dump_xml (PrintWriter out)
  {
    out.println("  <virtual_disk>");
    out.println("    <name>" + name + "</name>");
    out.println("    <key>" + key + "</key>");
    if (expiry == null)
    {
      out.println("    <expiry>0</expiry>");
    }
    else
    {
      out.println("    <expiry>" + expiry.getTime() + "</expiry>");
    }
    out.println("    <extents>");
    for (int loop = 0; loop < extents.size(); loop++)
    {
      Extent e = (Extent) extents.get(loop);
      out.println("      <extent>");
      out.println("        <disk>" + e.disk + "</disk>");
      out.println("        <size>" + e.size + "</size>");
      out.println("        <offset>" + e.offset + "</offset>");
      out.println("      </extent>");
    }
    out.println("    </extents>");
    out.println("  </virtual_disk>");

    return;
  }

  /*
   * Add a partition as a XenoPartition.
   * Chop the partition in to extents and of size "size" sectors
   * and add them to the virtual disk.
   */

  void
  add_new_partition (Partition partition, long size)
  {
    int loop;

    for (loop = 0; loop < partition.nr_sects / size; loop++)
    {
      Extent extent = new Extent();

      extent.disk = partition.major << 8;
      extent.disk = extent.disk | (partition.minor >> 5) << 5;
      extent.size = size;
      extent.offset = partition.start_sect + (size * loop);

      add_extent(extent);
    }
    
    return;
  }

  public String
  getName()
  {
    return name;
  }

  public String
  getKey()
  {
    return key;
  }

  public String
  getExpiry()
  {
    return expiry.toString();
  }

  public int
  getExtentCount()
  {
    return extents.size();
  }

  public Extent
  getExtent(int index)
  {
    return (Extent) extents.get(index);
  }
  
}
