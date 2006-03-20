	.file	"hypercall.S"
	.pred.safe_across_calls p1-p5,p16-p63
	.text
	.align 16
	.global dump_privop_counts#
	.proc dump_privop_counts#
dump_privop_counts:
	.prologue
	.body
	mov r2 = 0xffff
	;;
	break 0x1000
	;; 
	br.ret.sptk.many b0
	;;
	.endp dump_privop_counts#
	.align 16
	.global zero_privop_counts#
	.proc zero_privop_counts#
zero_privop_counts:
	.prologue
	.body
	mov r2 = 0xfffe
	;;
	break 0x1000
	;; 
	br.ret.sptk.many b0
	;;
	.endp zero_privop_counts#

