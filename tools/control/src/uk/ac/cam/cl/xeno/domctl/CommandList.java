package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;
import java.util.Vector;
import java.util.StringTokenizer;

public class CommandList extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    Domain [] domains = executeCommand(d);

    for (int loop = 0; loop < domains.length; loop++)
    {
      System.out.println ("id: " + domains[loop].id + 
			  " (" + domains[loop].name+ ")");
      System.out.println ("  processor: " + domains[loop].processor);
      System.out.println ("  has cpu: " + domains[loop].cpu);
      System.out.println ("  state: " + domains[loop].nstate + " " +
			  domains[loop].state);
      System.out.println ("  mcu advance: " + domains[loop].mcu);
      System.out.println ("  total pages: " + domains[loop].pages);
    }

    return 0;
  }

  public Domain[]
  executeCommand(Defaults d)
  {
    Runtime r = Runtime.getRuntime ();
    int rc = 0;
    Vector v = new Vector();
    String outline;
    BufferedReader in;
    Domain[] array;
    String output = null;

    try
      {
	Process start_p;
	String start_cmdarray[] = new String[1];
	int start_rc;
	start_cmdarray[0] = d.XIToolsDir + "xi_list";

	if (Settings.TEST) {
	  output += reportCommand (start_cmdarray);
	} else {
	  start_p = r.exec (start_cmdarray);
	  start_rc = start_p.waitFor ();
	  if (start_rc != 0) {
	    return null;
	  }
	  
	  in = new BufferedReader(
		   new InputStreamReader(start_p.getInputStream()));
    
	  outline = in.readLine();
	  while (outline != null)
	  {
	    Domain domain = new Domain();

	    StringTokenizer st = new StringTokenizer(outline);
	    if (st.hasMoreTokens())
	    {
	      domain.id = Integer.parseInt(st.nextToken());
	    }
	    if (st.hasMoreTokens())
	    {
	      domain.processor = Integer.parseInt(st.nextToken());
	    }
	    if (st.hasMoreTokens())
	    {
	      if (st.nextToken().equals("1"))
	      {
		domain.cpu = true;
	      }
	      else
	      {
		domain.cpu = false;
	      }
	    }
	    if (st.hasMoreTokens())
	    {
	      domain.nstate = Integer.parseInt(st.nextToken());
	    }
	    if (st.hasMoreTokens())
	    {
	      domain.state = st.nextToken().toLowerCase();
	    }
	    if (st.hasMoreTokens())
	    {
	      domain.mcu = Integer.parseInt(st.nextToken());
	    }
	    if (st.hasMoreTokens())
	    {
	      domain.pages = Integer.parseInt(st.nextToken());
	    }
	    if (st.hasMoreTokens())
	    {
	      domain.name = st.nextToken();
	    }
	    
	    v.add(domain);

	    outline = in.readLine();
	  }

	}
      }
    catch (Exception e) 
      {
	System.err.println ("Could not get domain list(" + e + ")");
	e.printStackTrace ();
	return null;
      }

    array = new Domain[v.size()];
    v.toArray(array);
    return array;
  }

  public String getName()
  {
    return "list";
  }

  public String getUsage()
  {
    return "";
  }

  public String getHelpText()
  {
    return
      "List domain information";
  }
}
