(** Intel.ml
 *
 *  various sundry Intel x86 definitions
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)


type register =
  | EBX
  | ECX
  | EDX
  | ESI
  | EDI
  | EBP
  | EAX
  | Error_code
  | Entry_vector
  | EIP
  | CS
  | EFLAGS
  | ESP
  | SS
  | ES
  | DS
  | FS
  | GS

type registers =
    { ebx : int32;
      ecx : int32;
      edx : int32;
      esi : int32;
      edi : int32;
      ebp : int32;
      eax : int32;
      error_code : int32;
      entry_vector : int32;
      eip : int32;
      cs : int32;
      eflags : int32;
      esp : int32;
      ss : int32;
      es : int32;
      ds : int32;
      fs : int32;
      gs : int32
    }

let null_registers =
  { ebx = 0l;
    ecx = 0l;
    edx = 0l;
    esi = 0l;
    edi = 0l;
    ebp = 0l;
    eax = 0l;
    error_code = 0l;
    entry_vector = 0l;
    eip = 0l;
    cs = 0l;
    eflags = 0l;
    esp = 0l;
    ss = 0l;
    es = 0l;
    ds = 0l;
    fs = 0l;
    gs = 0l
  }
