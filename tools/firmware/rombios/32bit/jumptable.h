#ifndef JUMPTABLE_H
#define JUMPTABLE_H

/*
   name of the section the 32bit BIOS must have and where the array of
   function poiners is built; hvmloader looks for this section and copies
   it into the lower BIOS in the 0xf000 segment
 */
#define JUMPTABLE_SECTION_NAME ".biosjumptable"

#endif
