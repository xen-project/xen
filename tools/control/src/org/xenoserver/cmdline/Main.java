package org.xenoserver.cmdline;

import java.util.LinkedList;
import java.util.NoSuchElementException;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

/**
 * Main class for the command-line xenctl interface.
 */
public class Main {
  static final ParseHelp help = new ParseHelp();
  private static final CommandParser domaincommands[] =
    { new ParseDomainNew(),
      new ParseDomainStart(),
      new ParseDomainStop(),
      new ParseDomainDestroy(),
      new ParseDomainList()
    };
  private static final CommandParser partitioncommands[] =
    { new ParsePartitionsAdd(),
      new ParsePartitionsList()
    };
  private static final CommandParser physicalcommands[] =
    { new ParsePhysicalGrant(),
      new ParsePhysicalRevoke(),
      new ParsePhysicalList()
    };
  private static final CommandParser vdcommands[] =
    { new ParseVdCreate(),
      new ParseVdDelete(),
      new ParseVdRefresh(),
      new ParseVdShow(),
      new ParseVdFree()
    };
  private static final CommandParser vbdcommands[] =
    { new ParseVbdCreate(),
      new ParseVbdShow()
    };
  private static final CommandParser commands[] =
    { help,
      new ParseGroup( "domain", domaincommands ),
      new ParseGroup( "partitions", partitioncommands ),
      new ParseGroup( "physical", physicalcommands ),
      new ParseScript(),
      new ParseGroup( "vd", vdcommands ),
      new ParseGroup( "vbd", vbdcommands )
    };
  /** The top-level parser. */
  static final CommandParser parser = new ParseGroup( null, commands );

  public static void executeArgList (Defaults d, LinkedList arglist)
     throws ParseFailedException, CommandFailedException 
  {
    if (arglist.size() == 0) {
      help.parse(null, null);
    } else {
      parser.parse(d, arglist);
    }
  }

  public static void main(String[] args) {
    Defaults d = new Defaults();
    int ec = -1;
    LinkedList arglist = new LinkedList();
    boolean seen_arg = false;
    String collected = null;
    for ( int i=0; i<args.length; i++ ) {
      if (!(args[i].startsWith("-"))) {
	if (seen_arg) {
	  collected += " " + args[i];
	} else {
	  arglist.add(args[i]);
	}
      }
      if (args[i].startsWith("-")) {
	if (collected != null) {
	  arglist.add ( collected );
	  collected = null;
	}
	collected = args[i];
	seen_arg = true;
      }
    }
    if (collected != null) {
      arglist.add( collected );
    }

    try {
      executeArgList (d, arglist);
      ec = 0;
    } catch (NoSuchElementException e) {
      help.parse(null, null);
    } catch (ParseFailedException e) {
      System.err.println( e.getMessage() );
    } catch (CommandFailedException e) {
      System.err.println( e.getMessage() );
    }

    System.exit(ec);
  }
}
