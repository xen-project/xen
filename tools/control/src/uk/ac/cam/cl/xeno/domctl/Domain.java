package uk.ac.cam.cl.xeno.domctl;

public class
Domain
{
  public int id;                                                /* domain id */
  public int processor;                                         /* processor */
  public boolean cpu;                                             /* has cpu */
  public int   nstate;                                              /* state */
  public String state;            /* running, interruptable, uninterruptable,
				                      wait, suspended, dying */
  public int mcu;                                            /* mcu advances */
  public int pages;                                           /* total pages */
  public String name;                                                /* name */

  Domain()
  {
    id = 0;
    processor = 0;
    cpu = false;
    nstate = 0;
    state = "";
    mcu = 0;
    pages = 0;
    name = "none";
  }
}
