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
      new ParseGroup( "vd", vdcommands ),
      new ParseGroup( "vbd", vbdcommands )
    };
  /** The top-level parser. */
  static final CommandParser parser = new ParseGroup( null, commands );

  public static void main(String[] args) {
    Defaults d = new Defaults();
    int ec = -1;
    LinkedList arglist = new LinkedList();
    for ( int i=0; i<args.length; i++ ) {
      arglist.add( args[i] );
    }

    if (args.length == 0) {
      help.parse(null, null);
    } else {
      try
      {
        parser.parse(d, arglist);
        ec = 0;
      } catch (NoSuchElementException e) {
          help.parse(null, null);
      } catch (ParseFailedException e) {
        System.err.println( e.getMessage() );
      } catch (CommandFailedException e) {
        System.err.println( e.getMessage() );
      }
    }

    System.exit(ec);
  }
}
