#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#define GCRY_CIPHER GCRY_CIPHER_SM4
#define GCRY_MODE GCRY_CIPHER_MODE_CFB
#define KEY_LENGTH 16 // 128 bits
#define BLOCK_SIZE 16 // 128 bits
#define IV_LENGTH 16  // 128 bits



int main() {
    unsigned char key[KEY_LENGTH] = "thisisverysecure";
    unsigned char iv[IV_LENGTH] = "thisisinitialvec";
    unsigned char* plaintext = "Hello, SM4 encryptionzzzzzzzzzzzzz!";
    size_t plaintext_len = strlen(plaintext);
    size_t padded_len = (plaintext_len / BLOCK_SIZE + 1) * BLOCK_SIZE;
    unsigned char *ciphertext = (unsigned char *)malloc(padded_len);
    unsigned char *decrypted = (unsigned char *)malloc(padded_len); 

    sm4_encrypt(plaintext, key, iv, plaintext_len, padded_len, KEY_LENGTH, KEY_LENGTH, GCRY_CIPHER, GCRY_MODE, ciphertext);

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < padded_len; ++i) {
    //     printf("%02X", ciphertext[i]);
    // }

    sm4_decrypt(iv, key, padded_len, KEY_LENGTH, IV_LENGTH, GCRY_CIPHER, GCRY_MODE, ciphertext, decrypted);
    // // Remove padding from the decrypted text
    // size_t decrypted_len = unpad(decrypted, padded_len);
    // printf("\nDecrypted: %.*s\n", (int)decrypted_len, decrypted);
    return 0;
}