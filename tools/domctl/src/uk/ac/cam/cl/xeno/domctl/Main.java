package uk.ac.cam.cl.xeno.domctl;

public class Main 
{
  static CommandHelp help = new CommandHelp ();
  static CommandNew newdom = new CommandNew ();
  static CommandStart start = new CommandStart ();
  static CommandStop stop = new CommandStop ();
  static CommandDestroy destroy = new CommandDestroy ();
  static Command commands[] = { help, newdom, start, stop, destroy };

  public static void main (String[] args)
  {
    Defaults d = new Defaults ();
    int ec = -1;

    if (args.length == 0) {
      ec = help.doCommand (d, args);
    } else {
      String c = args[0];
      int i;
      for (i = 0; i < commands.length; i ++) {
	if (commands[i].getName().equals(c)) {
	  if (commands[i].getFlagParameter (args, '?')) {
	    ec = help.doHelpFor (commands[i]);
	  } else {
	    ec = commands[i].doCommand (d, args);
	  }
	  break;
	}
      }
      if (i == commands.length) {
	System.out.println ("Unknown command " + c);
      }
    }

    System.exit (ec);
  }
}
