#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#define AES_KEY_LENGTH 32
#define BLOCK_SIZE 16 // 128 bits
#define HASH_FUNCTION GCRY_MD_SHA256

//return random character

unsigned char random_char_selector(int x)
{
    unsigned char charset[]= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return charset[x];
}

//return random string

unsigned char*  random_string_generator(int strlen)
{
    unsigned char *str = (unsigned char* )malloc((strlen + 1) * sizeof(char));
    if (!str) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    srand(time(NULL));
    //unsigned char str[strlen];
    int x;
    int i;
    for ( i=0; i<strlen-1 ; i++)
    {
        x = rand()%62;
        str[i] = random_char_selector(x);
    }
    str[i] = '\0';
    //printf("%s\n", str);
    return str;
}

int main() {
    
    unsigned char key[AES_KEY_LENGTH] = "0123456789abcdef01234567"; // 256-bit key
    unsigned char iv[16] = "abcdef0123456789"; // 128-bit IV
    
    int L = 1026;
    unsigned char *plaintext = random_string_generator(L);
    size_t plaintext_len = strlen(plaintext);
    

    size_t padded_len = (plaintext_len / BLOCK_SIZE + 1) * BLOCK_SIZE;
    unsigned char *ciphertext = (unsigned char *)malloc(padded_len);
    unsigned char *decrypted = (unsigned char *)malloc(padded_len);   
    

    // Test AES-256-CBC
    printf("Testing AES-256-CBC...\n");
    if (aes_cbc_encrypt(plaintext, key, iv, plaintext_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext) == 0) {
        printf("AES-256-CBC encryption successful.\n");
    } else {
        printf("AES-256-CBC encryption failed.\n");
    }
    unsigned char hmac[32];
    compute_hmac(key, sizeof(key), ciphertext, padded_len, hmac, HASH_FUNCTION);

    printf("HMAC: ");
    for (size_t i = 0; i < sizeof(hmac); i++) {
        printf("%02x", hmac[i]);
    }
    printf("\n");

    unsigned char cmac[16];
    compute_cmac(key, sizeof(key), ciphertext, padded_len, cmac, GCRY_MAC_CMAC_AES);

    printf("CMAC: ");
    for (size_t i = 0; i < sizeof(cmac); i++) {
        printf("%02x", cmac[i]);
    }
    printf("\n");
    printf("Testing AES-256-GCM...\n");

    // Compute GMAC for the plaintext
    unsigned char gmac_iv[12] = "123456789101";
    unsigned char gmac[16]; // GMAC output length is 128 bits (16 bytes)
    compute_gmac(key, plaintext, sizeof(key), plaintext_len, gmac, gmac_iv, GCRY_CIPHER_AES256);

    printf("GMAC: ");
    for (size_t i = 0; i < sizeof(gmac); i++) {
        printf("%02x", gmac[i]);
    }
    printf("\n");

    return 0;
}
