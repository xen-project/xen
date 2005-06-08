/* biossums.c  --- written by Eike W. for the Bochs BIOS */
/* adapted for the LGPL'd VGABIOS by vruppert */

#include <stdlib.h>
#include <stdio.h>

typedef unsigned char byte;

void check( int value, char* message );

#define LEN_BIOS_DATA 0x8000
#define MAX_OFFSET    (LEN_BIOS_DATA - 1)


#define BIOS_OFFSET 0x7FFF

long chksum_bios_get_offset( byte* data, long offset );
byte chksum_bios_calc_value( byte* data, long offset );
byte chksum_bios_get_value(  byte* data, long offset );
void chksum_bios_set_value(  byte* data, long offset, byte value );


#define PMID_LEN        20
#define PMID_CHKSUM     19

long chksum_pmid_get_offset( byte* data, long offset );
byte chksum_pmid_calc_value( byte* data, long offset );
byte chksum_pmid_get_value(  byte* data, long offset );
void chksum_pmid_set_value(  byte* data, long offset, byte value );


byte bios_data[LEN_BIOS_DATA];


int main( int argc, char* argv[] ) {

  FILE* stream;
  long  offset, tmp_offset;
  byte  cur_val = 0, new_val = 0;
  int   hits;


  if( argc != 2 ) {
    printf( "Error. Need a file-name as an argument.\n" );
    exit( EXIT_FAILURE );
  }

  if(( stream = fopen( argv[1], "rb" )) == NULL ) {
    printf( "Error opening %s for reading.\n", argv[1] );
    exit( EXIT_FAILURE );
  }
  if( fread( bios_data, 1, LEN_BIOS_DATA, stream ) >= LEN_BIOS_DATA ) {
    printf( "Error reading max. 32767 Bytes from %s.\n", argv[1] );
    fclose( stream );
    exit( EXIT_FAILURE );
  }
  fclose( stream );

  hits   = 0;
  offset = 0L;
  while( (tmp_offset = chksum_pmid_get_offset( bios_data, offset )) != -1L ) {
    offset  = tmp_offset;
    cur_val = chksum_pmid_get_value(  bios_data, offset );
    new_val = chksum_pmid_calc_value( bios_data, offset );
    printf( "\nPMID entry at: 0x%4lX\n", offset  );
    printf( "Current checksum:     0x%02X\n",   cur_val );
    printf( "Calculated checksum:  0x%02X  ",   new_val );
    hits++;
  }
  if( hits == 1 && cur_val != new_val ) {
    printf( "Setting checksum." );
    chksum_pmid_set_value( bios_data, offset, new_val );
  }
  if( hits >= 2 ) {
    printf( "Multiple PMID entries! No checksum set." );
  }
  if( hits ) {
    printf( "\n" );
  }


  offset  = 0L;
  offset  = chksum_bios_get_offset( bios_data, offset );
  cur_val = chksum_bios_get_value(  bios_data, offset );
  new_val = chksum_bios_calc_value( bios_data, offset );
  printf( "\nBios checksum at:   0x%4lX\n", offset  );
  printf( "Current checksum:     0x%02X\n",   cur_val );
  printf( "Calculated checksum:  0x%02X  ",   new_val );
  if( cur_val != new_val ) {
    printf( "Setting checksum." );
    chksum_bios_set_value( bios_data, offset, new_val );
  }
  printf( "\n" );


  if(( stream = fopen( argv[1], "wb" )) == NULL ) {
    printf( "Error opening %s for writing.\n", argv[1] );
    exit( EXIT_FAILURE );
  }
  if( fwrite( bios_data, 1, LEN_BIOS_DATA, stream ) < LEN_BIOS_DATA ) {
    printf( "Error writing 32KBytes to %s.\n", argv[1] );
    fclose( stream );
    exit( EXIT_FAILURE );
  }
  fclose( stream );

  return( EXIT_SUCCESS );
}


void check( int okay, char* message ) {

  if( !okay ) {
    printf( "\n\nError. %s.\n", message );
    exit( EXIT_FAILURE );
  }
}


long chksum_bios_get_offset( byte* data, long offset ) {

  return( BIOS_OFFSET );
}


byte chksum_bios_calc_value( byte* data, long offset ) {

  int   i;
  byte  sum;

  sum = 0;
  for( i = 0; i < MAX_OFFSET; i++ ) {
    sum = sum + *( data + i );
  }
  sum = -sum;          /* iso ensures -s + s == 0 on unsigned types */
  return( sum );
}


byte chksum_bios_get_value( byte* data, long offset ) {

  return( *( data + BIOS_OFFSET ) );
}


void chksum_bios_set_value( byte* data, long offset, byte value ) {

  *( data + BIOS_OFFSET ) = value;
}


byte chksum_pmid_calc_value( byte* data, long offset ) {

  int           i;
  int           len;
  byte sum;

  len = PMID_LEN;
  check( offset + len <= MAX_OFFSET, "PMID entry length out of bounds" );
  sum = 0;
  for( i = 0; i < len; i++ ) {
    if( i != PMID_CHKSUM ) {
      sum = sum + *( data + offset + i );
    }
  }
  sum = -sum;
  return( sum );
}


long chksum_pmid_get_offset( byte* data, long offset ) {

  long result = -1L;

  while( offset + PMID_LEN < MAX_OFFSET ) {
    offset = offset + 1;
    if( *( data + offset + 0 ) == 'P' && \
        *( data + offset + 1 ) == 'M' && \
        *( data + offset + 2 ) == 'I' && \
        *( data + offset + 3 ) == 'D' ) {
      result = offset;
      break;
    }
  }
  return( result );
}


byte chksum_pmid_get_value( byte* data, long offset ) {

  check( offset + PMID_CHKSUM <= MAX_OFFSET, "PMID checksum out of bounds" );
  return(  *( data + offset + PMID_CHKSUM ) );
}


void chksum_pmid_set_value( byte* data, long offset, byte value ) {

  check( offset + PMID_CHKSUM <= MAX_OFFSET, "PMID checksum out of bounds" );
  *( data + offset + PMID_CHKSUM ) = value;
}
