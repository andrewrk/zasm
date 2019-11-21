	.text
	.globl	_start
_start:
	adrp	x1, msg
	mov	w0, 1
	add	x1, x1, #288
	mov	w8, #64
	mov	w2, #14
	svc	#0
	mov	x0, xzr
	mov	w8, #93
	svc	#0

	.section	.rodata,"a"
msg:
	.ascii	"Hello, world!\n"
	.size	msg, 14
