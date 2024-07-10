//#include "../../../install/include/gcrypt.h"
#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#define AES_KEY_LENGTH 32
#define BLOCK_SIZE 16 // 128 bits

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

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


    // Test AES-256-CTR
    printf("Testing AES-256-CTR...\n");
    if (aes_ctr_encrypt(plaintext, key, iv, plaintext_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext) == 0) {
        printf("AES-256-CTR encryption successful.\n");
    } else {
        printf("AES-256-CTR encryption failed.\n");
    }

    printf("Decrypting AES-256-CTR...\n");
    aes_ctr_decrypt(ciphertext, key, iv, plaintext_len, sizeof(key), sizeof(iv), ciphertext, GCRY_CIPHER_AES256, decrypted);



    // Test AES-256-CBC
    printf("Testing AES-256-CBC...\n");
    if (aes_cbc_encrypt(plaintext, key, iv, plaintext_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext) == 0) {
        printf("AES-256-CBC encryption successful.\n");
    } else {
        printf("AES-256-CBC encryption failed.\n");
    }

    printf("Decrypting AES-256-CBC...\n");
    aes_cbc_decrypt(ciphertext, key, iv, padded_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext, decrypted);
    size_t unpadded_len = unpad(decrypted, padded_len);




    // Test AES-256-CFB
    printf("Testing AES-256-CFB...\n");
    if (aes_cfb_encrypt(plaintext, key, iv, plaintext_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext) == 0) {
        printf("AES-256-CFB encryption successful.\n");
    } else {
        printf("AES-256-CFB encryption failed.\n");
    }
    printf("Decrypting AES-256-CFB...\n");
    aes_cfb_decrypt(ciphertext, key, iv, plaintext_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext, decrypted);



    // Test AES-256-OFB
    
    printf("Testing AES-256-OFB...\n");
    if (aes_ofb_encrypt(plaintext, key, iv, plaintext_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext) == 0) {
        printf("AES-256-OFB encryption successful.\n");
    } else {
        printf("AES-256-OFB encryption failed.\n");
    }
    printf("Decrypting AES-256-OFB...\n");
    aes_ofb_decrypt(ciphertext, key, iv, plaintext_len, sizeof(key), sizeof(iv), GCRY_CIPHER_AES256, ciphertext, decrypted);

    return 0;
}
