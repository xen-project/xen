package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;

public class CommandDestroy extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    Runtime r = Runtime.getRuntime ();
    int domain_id = getIntParameter(args, 'n', 0);
    boolean force = getFlagParameter(args, 'f');
    int rc = 0;

    if (domain_id == 0) {
      System.err.println ("Expected -n<domain_id>");
      rc = -1;
      return rc;
    }

    try
      {
	Process destroy_p;
	String destroy_cmdarray[] = force ? new String[3] : new String[2];
	int destroy_rc;
	int idx = 0;
	destroy_cmdarray[idx++] = d.XIToolsDir + "xi_destroy";
	if (force) {
	  destroy_cmdarray[idx++] = "-f";
	}
	destroy_cmdarray[idx++] = "" + domain_id;

	if (Settings.TEST) {
	  reportCommand (destroy_cmdarray);
	} else {
	  destroy_p = r.exec (destroy_cmdarray);
	  destroy_rc = destroy_p.waitFor ();
	  
	  if (destroy_rc != 0) {
	    return reportXIError ("Could not destroy domain", destroy_cmdarray);
	  }
	}
      }
    catch (Exception e) 
      {
	System.err.println ("Could not destroy domain (" + e + ")");
	e.printStackTrace ();
	rc = -1;
      }

    return rc;
  }

  public String getName()
  {
    return "destroy";
  }

  public String getUsage()
  {
    return "[-f] [-n<domain_id>]";
  }

  public String getHelpText()
  {
    return
      "Destory the specified domain.  -f forcibly destroys it.";
  }
}
