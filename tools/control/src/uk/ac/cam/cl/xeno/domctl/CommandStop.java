package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;

public class CommandStop extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    int domain_id = getIntParameter(args, 'n', 0);
    String output;

    if (domain_id == 0) {
      System.err.println ("Expected -n<domain_id>");
      return -1;
    }

    output = executeCommand(d, domain_id);
    if (output != null)
    {
      System.err.println(output);
      return -1;
    }
    return 0;
  }

  public String
  executeCommand(Defaults d,
		 int domain_id)
  {
    Runtime r = Runtime.getRuntime ();
    String output = null;

    try
      {
	Process stop_p;
	String stop_cmdarray[] = new String[2];
	int stop_rc;
	stop_cmdarray[0] = d.XIToolsDir + "xi_stop";
	stop_cmdarray[1] = "" + domain_id;

	if (Settings.TEST) {
	  output += reportCommand (stop_cmdarray);
	} else {
	  stop_p = r.exec (stop_cmdarray);
	  stop_rc = stop_p.waitFor ();
	  
	  if (stop_rc != 0) {
	    return reportXIError ("Could not stop domain", stop_cmdarray);
	  }
	}
      }
    catch (Exception e) 
      {
	return ("Could not stop new domain (" + e + ")");
      }

    return output;
  }

  public String getName()
  {
    return "stop";
  }

  public String getUsage()
  {
    return "[-n<domain_id>]";
  }

  public String getHelpText()
  {
    return
      "Stop the specified domain.";
  }
}
