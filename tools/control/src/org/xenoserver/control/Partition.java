/*
 * Partition.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

import java.io.PrintWriter;

public class
Partition
{
  int major;
  int minor;
  long blocks;
  long start_sect;
  long nr_sects;
  String name;
  boolean xeno;

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
    p.xeno = xeno;

    return p;
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

  public int
  getMajor()
  {
    return major;
  }

  public int
  getMinor()
  {
    return minor;
  }

  public long
  getBlocks()
  {
    return blocks;
  }
  
  public long
  getStartSect()
  {
    return start_sect;
  }

  public long
  getNumSects()
  {
    return nr_sects;
  }
  
  public String
  getName()
  {
    return name;
  }

  public boolean
  getIsXeno()
  {
    return xeno;
  }

  public int hashCode() {
    final int PRIME = 1000003;
    int result = 0;
    result = PRIME * result + major;
    result = PRIME * result + minor;
    result = PRIME * result + (int) (blocks >>> 32);
    result = PRIME * result + (int) (blocks & 0xFFFFFFFF);
    result = PRIME * result + (int) (start_sect >>> 32);
    result = PRIME * result + (int) (start_sect & 0xFFFFFFFF);
    result = PRIME * result + (int) (nr_sects >>> 32);
    result = PRIME * result + (int) (nr_sects & 0xFFFFFFFF);
    if (name != null) {
      result = PRIME * result + name.hashCode();
    }

    return result;
  }

  public boolean equals(Object oth) {
    if (this == oth) {
      return true;
    }

    if (oth == null) {
      return false;
    }

    if (oth.getClass() != getClass()) {
      return false;
    }

    Partition other = (Partition) oth;

    if (this.major != other.major) {
      return false;
    }

    if (this.minor != other.minor) {
      return false;
    }

    if (this.blocks != other.blocks) {
      return false;
    }

    if (this.start_sect != other.start_sect) {
      return false;
    }

    if (this.nr_sects != other.nr_sects) {
      return false;
    }
    if (this.name == null) {
      if (other.name != null) {
        return false;
      }
    } else {
      if (!this.name.equals(other.name)) {
        return false;
      }
    }

    return true;
  }

  /**
   * @return An Extent covering this partiton.
   */
  public Extent toExtent()
  {
    Extent e = new Extent();
    // Build 16-bit disk number.. high 8 bits are the major
    e.disk = major << 8;
    // Low 8 bits are the minor, but bottom 5 need to be cleared
    // as they are the partition number, not the disk number
    e.disk |= ( minor & 0xE0 );
    e.offset = start_sect;
    e.size = nr_sects;
    return e;
  }
  
  /**
   * @param e Extent to compare this partition to.
   * @return True if this partition covers the same disk area as the given extent.
   */
  public boolean matchesExtent( Extent e )
  {
    if ( e.getMajor() != major )
      return false;
    if ( e.getMinor() != minor )
      return false;
    if ( e.offset != start_sect )
      return false;
    if ( e.size != nr_sects )
      return false;
      
    return true;
  }
}
