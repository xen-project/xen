/*
 * Extent.java
 * 03.03.26 aho creation
 */

package uk.ac.cam.cl.xeno.vdmanager;

public class
Extent
{
  int disk;
  long offset;                                           /* offset into disk */
  long size;                      /* size of this extent in 512 byte sectors */
}
