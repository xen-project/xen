--- ../../linux-2.6.7/arch/ia64/kernel/minstate.h	2004-06-15 23:19:52.000000000 -0600
+++ arch/ia64/minstate.h	2005-04-01 12:56:01.000000000 -0700
@@ -45,7 +45,7 @@
 (pKStk) tpa r1=sp;				/* compute physical addr of sp	*/		\
 (pUStk)	addl r1=IA64_STK_OFFSET-IA64_PT_REGS_SIZE,r1;	/* compute base of memory stack */	\
 (pUStk)	mov r23=ar.bspstore;				/* save ar.bspstore */			\
-(pUStk)	dep r22=-1,r22,61,3;			/* compute kernel virtual addr of RBS */	\
+(pUStk)	dep r22=-1,r22,60,4;			/* compute kernel virtual addr of RBS */	\
 	;;											\
 (pKStk) addl r1=-IA64_PT_REGS_SIZE,r1;		/* if in kernel mode, use sp (r12) */		\
 (pUStk)	mov ar.bspstore=r22;			/* switch to kernel RBS */			\
@@ -65,7 +65,7 @@
 #endif
 
 #ifdef MINSTATE_PHYS
-# define MINSTATE_GET_CURRENT(reg)	mov reg=IA64_KR(CURRENT);; dep reg=0,reg,61,3
+# define MINSTATE_GET_CURRENT(reg)	mov reg=IA64_KR(CURRENT);; dep reg=0,reg,60,4
 # define MINSTATE_START_SAVE_MIN	MINSTATE_START_SAVE_MIN_PHYS
 # define MINSTATE_END_SAVE_MIN		MINSTATE_END_SAVE_MIN_PHYS
 #endif
@@ -172,7 +172,7 @@
 	;;											\
 .mem.offset 0,0; st8.spill [r16]=r15,16;							\
 .mem.offset 8,0; st8.spill [r17]=r14,16;							\
-	dep r14=-1,r0,61,3;									\
+	dep r14=-1,r0,60,4;									\
 	;;											\
 .mem.offset 0,0; st8.spill [r16]=r2,16;								\
 .mem.offset 8,0; st8.spill [r17]=r3,16;								\
