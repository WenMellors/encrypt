#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <emmintrin.h>

#include "tables.h"
#include "aes.h"
#include "aes_ni_support.h"

#define AESNI 1

/****************expand crypt key*****************/ 
// rotate row of a word
void RotWord(unsigned char *s) {
	uint32_t *d = (uint32_t *)s; 
	asm("rorl $8, %0" : "=g"(*d) : "0"(*d));
}

// key schedule to expand key
void key_schedule_core(unsigned char *word, int i/*teration*/) {
	// rotate word
	RotWord(word);

	// replace each bytes by S-Box
	for (int j=0; j<4; j++) {
		word[j] = sbox[ word[j] ];
	}

	// XOR with round key
	word[0] ^= Rcon[i];
}

int aes_expand_key(const unsigned char *in_key, unsigned char *out_keys) {
	#define n 16
	memcpy(out_keys, in_key, n); // init

	int rcon_int = 1;
	int bytes_done = 16;

	while (bytes_done < 11*16) { 
		unsigned char tmp[4];

		memcpy(tmp, out_keys + bytes_done - 4, 4);

		// key schedule core
		key_schedule_core(tmp, rcon_int);
		rcon_int++;

		for (int i=0; i<4; i++) {
			tmp[i] ^= out_keys[bytes_done - n + i];
		}

		memcpy(out_keys + bytes_done, tmp, 4);
		bytes_done += 4;

		for (int i=0; i<3; i++) {
			memcpy(tmp, out_keys + bytes_done - 4, 4);
			for (int j=0; j<4; j++) {
				tmp[j] ^= out_keys[bytes_done - n + j];
			}

			memcpy(out_keys + bytes_done, tmp, 4);
			bytes_done += 4;
		}
	} 
	return 0;
}

/****************expand decrypt key*****************/ 
void aes_decryption_keys(const unsigned char *keys) {
    
    // check is support  aes-ni
	int aesni = is_aesni_support();

	if (aesni) {
		asm __volatile__ (
		"movq %[keys], %%r15;"    // save the keys pointer for easy pointer arithmetic
		"movl $1, %%ecx;"         // set loop counter (int round=1)
		"_loop:"                  
		"addq $16, %%r15;"        // move pointer to keys + (round * 16)
		"aesimc (%%r15), %%xmm0;" // perform InverseMixColumns
		"movdqa %%xmm0, (%%r15);" // save result back
		"inc %%ecx;"
		"cmp $9, %%ecx;"          
		"jle _loop;"              // loop if round <= 9
		:[keys] "=m"(keys)
		:
		: "%r15", "%ecx", "%xmm0", "cc", "memory"
		);
	}
	else {
		for (int round=1; round <= 9; round++) {
			InvMixColumns((unsigned char *)keys + (round * 16));
		}
	}
}

/****************encrypt and decrypt*****************/ 
void AddRoundKey(unsigned char *state, const unsigned char *keys) {

	__m128i state_val = _mm_load_si128((__m128i const *)state);
	__m128i key_val = _mm_load_si128((__m128i const *)keys);
	__m128i result    = _mm_xor_si128(state_val, key_val);

	_mm_storeu_si128((__m128i *)state, result);
}

void SubBytes(unsigned char *state) {
	// Replace bytes by S-Box
	for (int i=0; i<16; i++) {
		state[i] = sbox [ state[i] ];
	}
}

void InvSubBytes(unsigned char *state) {
	// Replace bytes by inverse S-Box
	for (int i=0; i<16; i++) {
		state[i] = invsbox [ state[i] ];
	}
}

void ShiftRows(unsigned char *state, int inverse) {
	uint32_t cols[4];

	for (int i=1; i<=3; i++) {
	
		cols[i] = (state[4*0 + i] << 24) | (state[4*1 + i] << 16) | (state[4*2 + i] << 8) | (state[4*3 + i]);

		uint8_t steps = 8*i;

		if (inverse == true) {
			 asm("rorl %1, %0"
			: "=g"(cols[i])
			: "cI"(steps), "0"(cols[i]));
		}
		else {
			asm("roll %1, %0"
			: "=g"(cols[i])
			: "cI"(steps), "0"(cols[i]));
		}

		// Extract the bits back and place back into the state
		for (int j = 0; j<4; j++) {
			state[4*j + i] = ((cols[i] >> (3-j) * 8) & 0xff);
		}
	}
}

void MixColumns(unsigned char *state) {

	for (int col=0; col<4; col++) {
		unsigned char r[4];
		unsigned char a[4];
		
        memcpy(a, state + col*4, 4);

		// use GF to apply matrix multiplication
		r[0] = gmul2[a[0]] ^ gmul3[a[1]] ^ a[2] ^ a[3];
		r[1] = a[0] ^ gmul2[a[1]] ^ gmul3[a[2]] ^ a[3];
		r[2] = a[0] ^ a[1] ^ gmul2[a[2]] ^ gmul3[a[3]];
		r[3] = gmul3[a[0]] ^ a[1] ^ a[2] ^ gmul2[a[3]];

		// Copy the answer back to the state
		memcpy(state + col * 4, r, 4);
	}
}

void InvMixColumns(unsigned char *state) {
	for (int col=0; col<4; col++) {
		
        unsigned char r[4];
		unsigned char a[4];

		memcpy(a, state + col*4, 4);

		// use GF to apply matrix multiplication
		r[0] = gmul14[a[0]] ^ gmul11[a[1]] ^ gmul13[a[2]] ^ gmul9[a[3]];
		r[1] = gmul9[a[0]] ^ gmul14[a[1]] ^ gmul11[a[2]] ^ gmul13[a[3]];
		r[2] = gmul13[a[0]] ^ gmul9[a[1]] ^ gmul14[a[2]] ^ gmul11[a[3]];
		r[3] = gmul11[a[0]] ^ gmul13[a[1]] ^ gmul9[a[2]] ^ gmul14[a[3]];

		// Copy the answer back to the state
		memcpy(state + col*4, r, 4);
	}
}

void aes_encrypt_aesni(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {
	asm __volatile__ (
			"movq %[keys], %%r15;"         // keep the pointer for easy pointer arithmetic
			"movdqa %[plaintext], %%xmm0;" // load plaintext
			"pxor (%%r15), %%xmm0;"        // perform whitening

			"mov $1, %%ecx;"          // initialize round counter
			"_encrypt_roundloop:"             
			"addq $16, %%r15;"        // move the pointer to the next round key
			"aesenc (%%r15), %%xmm0;" // perform AES round
			"inc %%ecx;"
			"cmp $10, %%ecx;"
			"jl _encrypt_roundloop;" // for (i=1; i<10; i++)

			"addq $16, %%r15;"            // move the pointer one last time
			"aesenclast (%%r15), %%xmm0;" // perform the final AES round
			"movdqa %%xmm0, %[state];"    // move the state back to the memory address

			:[state] "=m"(*state)
			:[plaintext] "m"(*plaintext), [keys] "m"(keys)
			:"%xmm0", "memory", "%ecx", "cc", "%r15"
			);
}

void aes_encrypt_c(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {
	// init
	memcpy(state, plaintext, 16);

	AddRoundKey(state, keys /*+ 0 */);

	// rounds
	for (int round = 1; round < 10; round++) {
		SubBytes(state);
		ShiftRows(state, 0 /* not inverse */);
		MixColumns(state);
		AddRoundKey(state, keys + (round * 16));
	}

	// final	
	SubBytes(state);
	ShiftRows(state, 0 /* not inverse */);
	AddRoundKey(state, keys + 10*16);
}

void aes_encrypt(const unsigned char *plaintext, unsigned char *state, const unsigned char *keys) {
	int aesni_support = is_aesni_support();

	if (aesni_support) {
		// printf("using aesni\n");
		aes_encrypt_aesni(plaintext,state,keys);
	} else {
		aes_encrypt_c(plaintext,state,keys);
	}
	
}

/****************decrypt*****************/ 
void aes_decrypt_aesni(const unsigned char *ciphertext, unsigned char *state, const unsigned char *keys) {
	   asm __volatile__ (
            "movq %[keys], %%r15;"         // keep the pointer for easy pointer arithmetic
			"addq $160, %%r15;"            // move the pointer to keys + 10*16
            "movdqa %[plaintext], %%xmm0;" // load plaintext
            "pxor (%%r15), %%xmm0;"        // perform whitening

            "mov $9, %%ecx;"          // initialize round counter
            "_decrypt_roundloop:"
            "subq $16, %%r15;"        // move the pointer to the "next" round key
            "aesdec (%%r15), %%xmm0;" // perform AES round
            "dec %%ecx;"
            "cmp $1, %%ecx;"
            "jge _decrypt_roundloop;" 

            "subq $16, %%r15;"            // move the pointer one last time
            "aesdeclast (%%r15), %%xmm0;" // perform the final AES round
            "movdqa %%xmm0, %[state];"    // move the state back to the memory address

            :[state] "=m"(*state)
            :[plaintext] "m"(*ciphertext), [keys] "m"(keys)
            :"%xmm0", "memory", "%ecx", "cc", "%r15"
            );
}

void aes_decrypt_c(const unsigned char *ciphertext, unsigned char *state, const unsigned char *keys) {

	// init
	memcpy(state, ciphertext, 16);

	AddRoundKey(state, keys + 10*16);

	// rounds
	for (int round = 9; round >= 1; round--) {
		InvSubBytes(state);
		InvShiftRows(state);
		InvMixColumns(state);
		AddRoundKey(state, keys + (round * 16));
	}

	// final	
	InvSubBytes(state);
	InvShiftRows(state);
	AddRoundKey(state, keys + 0);
}


void aes_decrypt(const unsigned char *ciphertext, unsigned char *state, const unsigned char *keys) {

	int aesni_support = is_aesni_support();

	if (aesni_support) {
		// printf("using aesni\n");
		aes_decrypt_aesni(ciphertext,state,keys);
	} else {
		aes_decrypt_c(ciphertext,state,keys);
	}
}
