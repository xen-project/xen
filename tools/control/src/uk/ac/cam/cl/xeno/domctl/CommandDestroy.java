package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;

public class CommandDestroy extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    int domain_id = getIntParameter(args, 'n', 0);
    boolean force = getFlagParameter(args, 'f');
    int rc = 0;
    String output;

    if (domain_id == 0) {
      System.err.println ("Expected -n<domain_id>");
      rc = -1;
      return rc;
    }

    output = executeCommand(d, domain_id, force);
    if (output != null)
    {
      System.err.println(output);
      return -1;
    }
    return 0;
  }

  public String
  executeCommand(Defaults d,
		 int domain_id,
		 boolean force)
  {
    Runtime r = Runtime.getRuntime ();
    String output = null;

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
	  output += reportCommand (destroy_cmdarray);
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
	return ("Could not destroy domain (" + e + ")");
      }

    return output;
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
