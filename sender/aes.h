#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

/*gen key*/ 
int aes_expand_key(const unsigned char *in_key, unsigned char *out_keys);
void aes_decryption_keys(const unsigned char *keys);

/*encrypt and decrypt*/ 
void AddRoundKey(unsigned char *state, const unsigned char *keys);
void SubBytes(unsigned char *state);
void aes_encrypt_aesni(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *keys);
void aes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *keys);
void aes_encrypt_c(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *keys);
void aes_decrypt_aesni(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *keys);
void aes_decrypt_c(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *keys);
void aes_decrypt(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *keys);
void ShiftRows(unsigned char *state, int inverse);
void InvSubBytes(unsigned char *state);
void InvMixColumns(unsigned char *state);
void MixColumns(unsigned char *state);

#define InvShiftRows(state) ShiftRows(state, 1)