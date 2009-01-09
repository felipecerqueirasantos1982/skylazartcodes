	.file "fork.s"
	.text

.globl main
main:
	xorl %eax, %eax
	inc %ax
	inc %ax
	int $0x80

	test %eax, %eax
	jz child
	
	xorl %eax, %eax
	xorl %ebx, %ebx
	inc %ax
	int $0x80
child:
	movl $24, %eax
	int $0x80
	
	movl $1, %eax
	movl $1, %ebx
	int $0x80
	