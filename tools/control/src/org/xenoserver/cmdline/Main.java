package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class Main {
  static final ParseHelp help = new ParseHelp();
  static final CommandParser domaincommands[] =
    { new ParseDomainNew(),
      new ParseDomainStart(),
      new ParseDomainStop(),
      new ParseDomainDestroy(),
      new ParseDomainList()
    };
  static final CommandParser partitioncommands[] =
    { new ParsePartitionsAdd(),
      new ParsePartitionsList()
    };
  static final CommandParser physicalcommands[] =
    { new ParsePhysicalGrant(),
      new ParsePhysicalRevoke(),
      new ParsePhysicalList()
    };
  static final CommandParser vdcommands[] =
    { new ParseVdCreate(),
      new ParseVdShow(),
      new ParseVdFree()
    };
  static final CommandParser commands[] =
    { help,
      new ParseGroup( "domain", domaincommands ),
      new ParseGroup( "partitions", partitioncommands ),
      new ParseGroup( "physical", physicalcommands ),
      new ParseGroup( "vd", vdcommands )
    };
  static final CommandParser parser = new ParseGroup( null, commands );

  public static void main(String[] args) {
    Defaults d = new Defaults();
    int ec = -1;
    LinkedList arglist = new LinkedList();
    for ( int i=0; i<args.length; i++ )
      arglist.add( args[i] );

    if (args.length == 0) {
      help.parse(d, arglist);
    } else {
      try
      {
        parser.parse(d, arglist);
        ec = 0;
      } catch (ParseFailedException e) {
        System.err.println( e.getMessage() );
      } catch (CommandFailedException e) {
        System.err.println( e.getMessage() );
      }
    }

    System.exit(ec);
  }
}
