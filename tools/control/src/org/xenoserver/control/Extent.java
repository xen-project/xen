/*
 * Extent.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

public class
Extent
{
  int disk;
  long offset;                                           /* offset into disk */
  long size;                      /* size of this extent in 512 byte sectors */

  public int
  getDisk()
  {
    return disk;
  }

  public long
  getOffset()
  {
    return offset;
  }

  public long
  getSize()
  {
    return size;
  }
  
  public int
  getMajor()
  {
    return disk >> 8;
  }
  
  public int
  getMinor()
  {
    return disk & 0xFF;
  }
  
  public int hashCode() {
    final int PRIME = 1000003;
    int result = 0;
    result = PRIME * result + disk;
    result = PRIME * result + (int) (offset >>> 32);
    result = PRIME * result + (int) (offset & 0xFFFFFFFF);
    result = PRIME * result + (int) (size >>> 32);
    result = PRIME * result + (int) (size & 0xFFFFFFFF);

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

    Extent other = (Extent) oth;

    if (this.disk != other.disk) {
      return false;
    }

    if (this.offset != other.offset) {
      return false;
    }

    if (this.size != other.size) {
      return false;
    }

    return true;
  }

}
