#include "cpu-usage.h"
#include "compiled.h"
#include "runtime.h"
#include "cycle-timings.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysinfo.h>


#define GCRY_CIPHER GCRY_CIPHER_AES256
#define AES_KEY_LENGTH 32
#define BLOCK_SIZE 16 // 128 bits

int main()
{
    int (*aes_encryption_functions[])(unsigned char*, unsigned char*, unsigned char*, size_t, size_t, size_t, int, unsigned char*) = {
        aes_cbc_encrypt,
        aes_ctr_encrypt,
        aes_ofb_encrypt,
        aes_cfb_encrypt,
    };

    const char *aes_function_names[] = {
        "AES-CBC-Encryption",
        "AES-CTR-Encryption",
        "AES-OFB-Encryption",
        "AES-CFB-Encryption"
    };
    size_t aes_num_functions = sizeof(aes_encryption_functions) / sizeof(aes_encryption_functions[0]);



    for (size_t i = 0; i < aes_num_functions; i++) {
        unsigned char key[AES_KEY_LENGTH] = "0123456789abcdef01234567"; // 256-bit key
        unsigned char IV[16] = "abcdef0123456789"; // 128-bit IV
        
        int L = 1026;
        unsigned char *plaintext = random_string_generator(L);
        size_t plaintext_len = strlen(plaintext);
        

        size_t padded_len = (plaintext_len / BLOCK_SIZE + 1) * BLOCK_SIZE;
        unsigned char *ciphertext = (unsigned char *)malloc(padded_len);

        init();
        float time_spent = (cpu_time(aes_encryption_functions[i], plaintext, key, IV, plaintext_len, sizeof(key), sizeof(IV), GCRY_CIPHER, ciphertext))/1000;
        float cycles = cpu_cycles(aes_encryption_functions[i], plaintext, key, IV, plaintext_len, sizeof(key), sizeof(IV), GCRY_CIPHER, ciphertext);
        float thr = throughput(aes_encryption_functions[i], plaintext, key, IV, plaintext_len, sizeof(key), sizeof(IV), GCRY_CIPHER, ciphertext);
        double cpu_usage = getCurrentValue();

        printf("-------------------------------------------------------\n");
        printf("AES Mode: %s\n", aes_function_names[i]);
        printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", cycles);
        printf("Runtime: %f milliseconds\n", time_spent);
        printf("Throughput: %f Bytes/second\n", thr);
        printf("CPU Usage: %.2f%% \n", cpu_usage);
        printf("Processed Bytes: %ld bytes\n", plaintext_len);
        printf("\n");
    }

}
