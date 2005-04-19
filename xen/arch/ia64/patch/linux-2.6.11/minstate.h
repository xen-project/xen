 minstate.h |    4 ++--
 1 files changed, 2 insertions(+), 2 deletions(-)

Index: linux-2.6.11-xendiffs/arch/ia64/kernel/minstate.h
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/kernel/minstate.h	2005-04-06 22:51:31.170261541 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/kernel/minstate.h	2005-04-06 22:54:03.210575034 -0500
@@ -48,7 +48,7 @@
 (pUStk)	mov r24=ar.rnat;									\
 (pUStk)	addl r1=IA64_STK_OFFSET-IA64_PT_REGS_SIZE,r1;	/* compute base of memory stack */	\
 (pUStk)	mov r23=ar.bspstore;				/* save ar.bspstore */			\
-(pUStk)	dep r22=-1,r22,61,3;			/* compute kernel virtual addr of RBS */	\
+(pUStk)	dep r22=-1,r22,60,4;			/* compute kernel virtual addr of RBS */	\
 	;;											\
 (pKStk) addl r1=-IA64_PT_REGS_SIZE,r1;		/* if in kernel mode, use sp (r12) */		\
 (pUStk)	mov ar.bspstore=r22;			/* switch to kernel RBS */			\
@@ -57,7 +57,7 @@
 (pUStk)	mov ar.rsc=0x3;		/* set eager mode, pl 0, little-endian, loadrs=0 */		\
 
 #define MINSTATE_END_SAVE_MIN_PHYS								\
-	dep r12=-1,r12,61,3;		/* make sp a kernel virtual address */			\
+	dep r12=-1,r12,60,4;		/* make sp a kernel virtual address */			\
 	;;
 
 #ifdef MINSTATE_VIRT
