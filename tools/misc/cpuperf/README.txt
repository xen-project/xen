Usage
=====

Use either xen-cpuperf, cpuperf-perfcntr as appropriate to the system
in use.

To write:

    cpuperf -E <escr> -C <cccr> 

        optional: all numbers in base 10 unless specified

        -d             Debug mode
        -c <cpu>       CPU number
        -t <thread>    ESCR thread bits - default is 12 (Thread 0 all rings)
                         bit 0: Thread 1 in rings 1,2,3
                         bit 1: Thread 1 in ring 0
                         bit 2: Thread 0 in rings 1,2,3
                         bit 3: Thread 0 in ring 0
        -e <eventsel>  Event selection number
        -m <eventmask> Event mask bits
        -T <value>     ESCR tag value
        -k             Sets CCCR 'compare' bit
        -n             Sets CCCR 'complement' bit
        -g             Sets CCCR 'edge' bit
        -P <bit>       Set the specified bit in MSR_P4_PEBS_ENABLE
        -V <bit>       Set the specified bit in MSR_P4_PEBS_MATRIX_VERT
        (-V and -P may be used multiple times to set multiple bits.)

To read:

    cpuperf -r    

        optional: all numbers in base 10 unless specified
    
        -c <cpu>       CPU number

<cccr> values:

    BPU_CCCR0
    BPU_CCCR1
    BPU_CCCR2
    BPU_CCCR3
    MS_CCCR0
    MS_CCCR1
    MS_CCCR2
    MS_CCCR3
    FLAME_CCCR0
    FLAME_CCCR1
    FLAME_CCCR2
    FLAME_CCCR3
    IQ_CCCR0
    IQ_CCCR1
    IQ_CCCR2
    IQ_CCCR3
    IQ_CCCR4
    IQ_CCCR5
    NONE - do not program any CCCR, used when setting up an ESCR for tagging

<escr> values:

    BSU_ESCR0
    BSU_ESCR1
    FSB_ESCR0
    FSB_ESCR1
    MOB_ESCR0
    MOB_ESCR1
    PMH_ESCR0
    PMH_ESCR1
    BPU_ESCR0
    BPU_ESCR1
    IS_ESCR0
    IS_ESCR1
    ITLB_ESCR0
    ITLB_ESCR1
    IX_ESCR0
    IX_ESCR1
    MS_ESCR0
    MS_ESCR1
    TBPU_ESCR0
    TBPU_ESCR1
    TC_ESCR0
    TC_ESCR1
    FIRM_ESCR0
    FIRM_ESCR1
    FLAME_ESCR0
    FLAME_ESCR1
    DAC_ESCR0
    DAC_ESCR1
    SAAT_ESCR0
    SAAT_ESCR1
    U2L_ESCR0
    U2L_ESCR1
    CRU_ESCR0
    CRU_ESCR1
    CRU_ESCR2
    CRU_ESCR3
    CRU_ESCR4
    CRU_ESCR5
    IQ_ESCR0
    IQ_ESCR1
    RAT_ESCR0
    RAT_ESCR1
    SSU_ESCR0
    SSU_ESCR1
    ALF_ESCR0
    ALF_ESCR1


Example configurations
======================

Note than in most cases there is a choice of ESCRs and CCCRs for
each metric although not all combinations are allowed. Each ESCR and
counter/CCCR can be used only once.

Mispredicted branches retired
=============================

cpuperf -E CRU_ESCR0 -C IQ_CCCR0 -e 3 -m 1
cpuperf -E CRU_ESCR0 -C IQ_CCCR1 -e 3 -m 1
cpuperf -E CRU_ESCR0 -C IQ_CCCR4 -e 3 -m 1
cpuperf -E CRU_ESCR1 -C IQ_CCCR2 -e 3 -m 1
cpuperf -E CRU_ESCR1 -C IQ_CCCR3 -e 3 -m 1
cpuperf -E CRU_ESCR1 -C IQ_CCCR5 -e 3 -m 1

Tracecache misses
=================

cpuperf -E BPU_ESCR0 -C BPU_CCCR0 -e 3 -m 1
cpuperf -E BPU_ESCR0 -C BPU_CCCR1 -e 3 -m 1
cpuperf -E BPU_ESCR1 -C BPU_CCCR2 -e 3 -m 1
cpuperf -E BPU_ESCR1 -C BPU_CCCR3 -e 3 -m 1

I-TLB
=====

cpuperf -E ITLB_ESCR0 -C BPU_CCCR0 -e 24 
cpuperf -E ITLB_ESCR0 -C BPU_CCCR1 -e 24 
cpuperf -E ITLB_ESCR1 -C BPU_CCCR2 -e 24 
cpuperf -E ITLB_ESCR1 -C BPU_CCCR3 -e 24 

 -m <n> : bit 0 count HITS, bit 1 MISSES, bit 2 uncacheable hit

 e.g. all ITLB misses -m 2

Load replays
============

cpuperf -E MOB_ESCR0 -C BPU_CCCR0 -e 3
cpuperf -E MOB_ESCR0 -C BPU_CCCR1 -e 3
cpuperf -E MOB_ESCR1 -C BPU_CCCR2 -e 3
cpuperf -E MOB_ESCR1 -C BPU_CCCR3 -e 3

 -m <n> : bit mask, replay due to...
           1: unknown store address
           3: unknown store data
           4: partially overlapped data access between LD/ST
           5: unaligned address between LD/ST

Page walks
==========

cpuperf -E PMH_ESCR0 -C BPU_CCCR0 -e 1
cpuperf -E PMH_ESCR0 -C BPU_CCCR1 -e 1
cpuperf -E PMH_ESCR1 -C BPU_CCCR2 -e 1
cpuperf -E PMH_ESCR1 -C BPU_CCCR3 -e 1

 -m <n> : bit 0 counts walks for a D-TLB miss, bit 1 for I-TLB miss

L2/L3 cache accesses
====================

cpuperf -E BSU_ESCR0 -C BPU_CCCR0 -e 12
cpuperf -E BSU_ESCR0 -C BPU_CCCR1 -e 12
cpuperf -E BSU_ESCR1 -C BPU_CCCR2 -e 12
cpuperf -E BSU_ESCR1 -C BPU_CCCR3 -e 12

 -m <n> : where the bit mask is:
           0: Read L2 HITS Shared
           1: Read L2 HITS Exclusive
           2: Read L2 HITS Modified
           3: Read L3 HITS Shared
           4: Read L3 HITS Exclusive
           5: Read L3 HITS Modified
           8: Read L2 MISS
           9: Read L3 MISS
          10: Write L2 MISS

Front side bus activity
=======================

cpuperf -E FSB_ESCR0 -C BPU_CCCR0 -e 23 -k -g
cpuperf -E FSB_ESCR0 -C BPU_CCCR1 -e 23 -k -g
cpuperf -E FSB_ESCR1 -C BPU_CCCR2 -e 23 -k -g
cpuperf -E FSB_ESCR1 -C BPU_CCCR3 -e 23 -k -g

 -m <n> : where the bit mask is for bus events:
           0: DRDY_DRV    Processor drives bus
           1: DRDY_OWN    Processor reads bus
           2: DRDY_OTHER  Data on bus not being sampled by processor
           3: DBSY_DRV    Processor reserves bus for driving
           4: DBSY_OWN    Other entity reserves bus for sending to processor
           5: DBSY_OTHER  Other entity reserves bus for sending elsewhere

 e.g. -m 3 to get cycles bus actually in use.

Pipeline clear (entire)
=======================

cpuperf -E CRU_ESCR2 -C IQ_CCCR0 -e 2
cpuperf -E CRU_ESCR2 -C IQ_CCCR1 -e 2
cpuperf -E CRU_ESCR2 -C IQ_CCCR4 -e 2
cpuperf -E CRU_ESCR3 -C IQ_CCCR2 -e 2
cpuperf -E CRU_ESCR3 -C IQ_CCCR3 -e 2
cpuperf -E CRU_ESCR3 -C IQ_CCCR5 -e 2

 -m <n> : bit mask:
           0: counts a portion of cycles while clear (use -g for edge trigger)
           1: counts each time machine clears for memory ordering issues
           2: counts each time machine clears for self modifying code

Instructions retired
====================

cpuperf -E CRU_ESCR0 -C IQ_CCCR0 -e 2
cpuperf -E CRU_ESCR0 -C IQ_CCCR1 -e 2
cpuperf -E CRU_ESCR0 -C IQ_CCCR4 -e 2
cpuperf -E CRU_ESCR1 -C IQ_CCCR2 -e 2
cpuperf -E CRU_ESCR1 -C IQ_CCCR3 -e 2
cpuperf -E CRU_ESCR1 -C IQ_CCCR5 -e 2

 -m <n> : bit mask:
           0: counts non-bogus, not tagged instructions
           1: counts non-bogus, tagged instructions
           2: counts bogus, not tagged instructions
           3: counts bogus, tagged instructions

 e.g. -m 3 to count legit retirements

Uops retired
============

cpuperf -E CRU_ESCR0 -C IQ_CCCR0 -e 1
cpuperf -E CRU_ESCR0 -C IQ_CCCR1 -e 1
cpuperf -E CRU_ESCR0 -C IQ_CCCR4 -e 1
cpuperf -E CRU_ESCR1 -C IQ_CCCR2 -e 1
cpuperf -E CRU_ESCR1 -C IQ_CCCR3 -e 1
cpuperf -E CRU_ESCR1 -C IQ_CCCR5 -e 1

 -m <n> : bit mask:
           0: Non-bogus
           1: Bogus

x87 FP uops
===========

cpuperf -E FIRM_ESCR0 -C FLAME_CCCR0 -e 4 -m 32768
cpuperf -E FIRM_ESCR0 -C FLAME_CCCR1 -e 4 -m 32768
cpuperf -E FIRM_ESCR1 -C FLAME_CCCR2 -e 4 -m 32768
cpuperf -E FIRM_ESCR1 -C FLAME_CCCR3 -e 4 -m 32768

Replay tagging mechanism
========================

Counts retirement of uops tagged with the replay tagging mechanism

cpuperf -E CRU_ESCR2 -C IQ_CCCR0 -e 9
cpuperf -E CRU_ESCR2 -C IQ_CCCR1 -e 9
cpuperf -E CRU_ESCR2 -C IQ_CCCR4 -e 9
cpuperf -E CRU_ESCR3 -C IQ_CCCR2 -e 9
cpuperf -E CRU_ESCR3 -C IQ_CCCR3 -e 9
cpuperf -E CRU_ESCR3 -C IQ_CCCR5 -e 9

 -m <n> : bit mask:
           0: Non-bogus (set this bit for all events listed below)
           1: Bogus

Set replay tagging mechanism bits with -P and -V:

  L1 cache load miss retired:      -P 0 -P 24 -P 25 -V 0
  L2 cache load miss retired:      -P 1 -P 24 -P 25 -V 0  (read manual)
  DTLB load miss retired:          -P 2 -P 24 -P 25 -V 0
  DTLB store miss retired:         -P 2 -P 24 -P 25 -V 1
  DTLB all miss retired:           -P 2 -P 24 -P 25 -V 0 -V 1

e.g. to count all DTLB misses

 cpuperf -E CRU_ESCR2 -C IQ_CCCR0 -e 9 -m 1 P 2 -P 24 -P 25 -V 0 -V 1

Front end event
===============

To count tagged uops:

cpuperf -E CRU_ESCR2 -C IQ_CCCR0 -e 8
cpuperf -E CRU_ESCR2 -C IQ_CCCR1 -e 8
cpuperf -E CRU_ESCR2 -C IQ_CCCR4 -e 8
cpuperf -E CRU_ESCR3 -C IQ_CCCR2 -e 8
cpuperf -E CRU_ESCR3 -C IQ_CCCR3 -e 8
cpuperf -E CRU_ESCR3 -C IQ_CCCR5 -e 8

 -m <n> : bit 0 for non-bogus uops, bit 1 for bogus uops

Must have another ESCR programmed to tag uops as required

cpuperf -E RAT_ESCR0 -C NONE -e 2
cpuperf -E RAT_ESCR1 -C NONE -e 2

 -m <n> : bit 1 for LOADs, bit 2 for STOREs

An example set of counters
===========================

# instructions retired
cpuperf -E CRU_ESCR0 -C IQ_CCCR0 -e 2 -m 3

# trace cache misses
cpuperf -E BPU_ESCR0 -C BPU_CCCR0 -e 3 -m 1

# L1 D cache misses (load misses retired)
cpuperf -E CRU_ESCR2 -C IQ_CCCR1 -e 9 -m 1 -P 0 -P 24 -P 25 -V 0

# L2 misses (load and store)
cpuperf -E BSU_ESCR0 -C BPU_CCCR1 -e 12 -m 1280

# I-TLB misses
cpuperf -E ITLB_ESCR1 -C BPU_CCCR2 -e 24 -m 2

# D-TLB misses (as PT walks)
cpuperf -E PMH_ESCR1 -C BPU_CCCR3 -e 1 -m 1

# Other 'bonus' counters would be:
#   number of loads executed - need both command lines
cpuperf -E RAT_ESCR0 -C NONE -e 2 -m 2
cpuperf -E CRU_ESCR3 -C IQ_CCCR3 -e 8 -m 3

#   number of mispredicted branches
cpuperf -E CRU_ESCR1 -C IQ_CCCR2 -e 3 -m 1

# x87 FP uOps
cpuperf -E FIRM_ESCR0 -C FLAME_CCCR0 -e 4 -m 32768

The above has counter assignments

0  Trace cache misses
1  L2 Misses
2  I-TLB misses
3  D-TLB misses
4  
5  
6  
7  
8  x87 FP uOps 
9  
10 
11 
12 Instructions retired
13 L1 D cache misses
14 Mispredicted branches
15 Loads executed
16 
17 

Counting instructions retired on each logical CPU
=================================================

cpuperf -E CRU_ESCR0 -C IQ_CCCR0 -e 2 -m 3 -t 12
cpuperf -E CRU_ESCR1 -C IQ_CCCR2 -e 2 -m 3 -t 3

Cannot count mispred branches as well due to CRU_ESCR1 use.
