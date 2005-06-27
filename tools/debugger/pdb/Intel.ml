(** Intel.ml
 *
 *  various sundry Intel x86 definitions
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)


type register =
  | EAX
  | ECX
  | EDX
  | EBX
  | ESP
  | EBP
  | ESI
  | EDI
  | EIP
  | EFL
  | CS
  | SS
  | DS
  | ES
  | FS
  | GS

type registers =
    { eax : int32;
      ecx : int32;
      edx : int32;
      ebx : int32;
      esp : int32;
      ebp : int32;
      esi : int32;
      edi : int32;
      eip : int32;
      efl : int32;
      cs  : int32;
      ss  : int32;
      ds  : int32;
      es  : int32;
      fs  : int32;
      gs  : int32
    }

let null_registers =
    { eax = 0l;
      ecx = 0l;
      edx = 0l;
      ebx = 0l;
      esp = 0l;
      ebp = 0l;
      esi = 0l;
      edi = 0l;
      eip = 0l;
      efl = 0l;
      cs  = 0l;
      ss  = 0l;
      ds  = 0l;
      es  = 0l;
      fs  = 0l;
      gs  = 0l
    }

