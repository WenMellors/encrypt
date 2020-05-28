int is_aesni_support(void) {
	int support;
	asm(
			"movl $1, %%eax;"
			"cpuid;"
			"andl $0x2000000, %%ecx;"
			"shrl $25, %%ecx;"
			"movb %%cl, %[support];"
			: [support] "=m"(support)
			: : "%eax", "%ebx", "%ecx", "%edx", "cc"
		);

	return support;
}
