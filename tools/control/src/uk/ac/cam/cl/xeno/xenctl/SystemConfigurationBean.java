/*
 * SystemConfigurationBean.java
 * 03.05.06 aho creation
 */

package uk.ac.cam.cl.xeno.xenctl;

import java.io.*;
import java.lang.Process;
import java.lang.Runtime;
import uk.ac.cam.cl.xeno.domctl.Defaults;

public class
SystemConfigurationBean
{
  Defaults defaults;

  public
  SystemConfigurationBean ()
  {
    defaults = new Defaults();
  }

  public Defaults
  getDefaults ()
  {
    return defaults;
  }

}
