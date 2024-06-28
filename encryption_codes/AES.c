#define _POSIX_C_SOURCE 200809L
#include "../install/include/gcrypt.h"
#include "cycle-timings.h"
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/random.h>
#include <string.h>
#include <time.h>
#include <sys/sysinfo.h>
#include "cpu-usage.h"
#define USE_AESNI




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

/*
int aes(unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;
    

    // Initialize Libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "Libgcrypt version mismatch\n");
        return 1;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Allocate memory for ciphertext
    unsigned char ciphertext[1038];
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Open cipher handle
    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        fprintf(stderr, "Failed to open cipher handle\n");
        return 1;
    }

    // Set key
    err = gcry_cipher_setkey(handle, key, 16);
    if (err) {
        fprintf(stderr, "Failed to set key: %s\n", gcry_strerror(err));
        return 1;
    }

    // Set IV
    err = gcry_cipher_setiv(handle, IV, 16);
    if (err) {
        fprintf(stderr, "Failed to set IV: %s\n", gcry_strerror(err));
        return 1;
    }

    // Encrypt plaintext
    err = gcry_cipher_encrypt(handle, ciphertext, plaintext_len + 16, plaintext, plaintext_len);
    if (err) {
        fprintf(stderr, "Encryption failed: %s\n", gcry_strerror(err));
        return 1;
    }



    // Clean up
    gcry_cipher_close(handle);
    //free(ciphertext);
    return 0;
}
*/


int aes_generic(unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len, int mode) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;
    

    // Initialize Libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "Libgcrypt version mismatch\n");
        return 1;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Allocate memory for ciphertext
    unsigned char ciphertext[1600];
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    // Open cipher handle
    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, mode, 0);
    if (err) {
        fprintf(stderr, "Failed to open cipher handle\n");
        return 1;
    }

    // Set key
    err = gcry_cipher_setkey(handle, key, 16);
    if (err) {
        fprintf(stderr, "Failed to set key: %s\n", gcry_strerror(err));
        return 1;
    }

    // Set IV
    err = gcry_cipher_setiv(handle, IV, 16);
    if (err) {
        fprintf(stderr, "Failed to set IV: %s\n", gcry_strerror(err));
        return 1;
    }

    // Encrypt plaintext
    err = gcry_cipher_encrypt(handle, ciphertext, plaintext_len + 16, plaintext, plaintext_len);
    if (err) {
        fprintf(stderr, "Encryption failed: %s\n", gcry_strerror(err));
        return 1;
    }

    // Clean up
    gcry_cipher_close(handle);
    //free(ciphertext);
    return 0;
}

int aes_256_ctr(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len) {
    return aes_generic(plaintext, key, IV, plaintext_len, key_len, IV_len, GCRY_CIPHER_MODE_CTR);
}


int aes_256_cbc(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len) {
    return aes_generic(plaintext, key, IV, plaintext_len, key_len, IV_len, GCRY_CIPHER_MODE_CBC);
}

int aes_256_cfb(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len) {
    return aes_generic(plaintext, key, IV, plaintext_len, key_len, IV_len, GCRY_CIPHER_MODE_CFB);
}

int aes_256_ofb(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len) {
    return aes_generic(plaintext, key, IV, plaintext_len, key_len, IV_len, GCRY_CIPHER_MODE_OFB);
}

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len)
{
    
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    int x = (*f)(plaintext, key, IV, plaintext_len, key_len, IV_len);

    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    const uint64_t ns = (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);
    float time_spent = ns;

    return time_spent;
}


//This measures CPU cycles for encryption process
float cpu_cycles(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len)
{

    //Measure the overhead of timing

    uint64_t timing_overhead;
    timing_overhead = measure_overhead();
    printf("Timing overhead: %lu clock cycles\n", timing_overhead);


    //Compute the length of processed data 

    int byte_length_of_processed_data = plaintext_len;
    float rate;

    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        temp = start_timer();

        int x = (*f)(plaintext, key, IV, plaintext_len, key_len, IV_len);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len)
{
    int byte_length_of_processed_data = plaintext_len;
    float time = cpu_time(f, plaintext, key, IV, plaintext_len, key_len, IV_len);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}


/*
//This measures execution runtime
int main()
{
    int L = 1025;

    unsigned char *plaintext = random_string_generator(L);
    size_t plaintext_len = strlen((unsigned char* )plaintext);

    unsigned char *key =random_string_generator(32);
    unsigned char *IV = random_string_generator(16);
    size_t key_len = 32;
    size_t IV_len = 16;


    float time_spent = cpu_time(aes, plaintext, key, IV, plaintext_len, key_len, IV_len)/1000000;
    float rate = cpu_cycles(aes, plaintext, key, IV, plaintext_len, key_len, IV_len);
    float Throughput = throughput(aes, plaintext, key, IV, plaintext_len, key_len, IV_len);


    //printf("Runtime: %f seconds\n", time_spent);
    printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
    printf("Runtime: %f milliseconds\n", time_spent);
    printf("Throughput: %f Bytes/second\n", Throughput);
    printf("Length: %ld", plaintext_len);
    printf("\n");

    return 0;

}
*/
int main()
{
    int (*aes_encryption_functions[])(unsigned char*, unsigned char*, unsigned char*, size_t, size_t, size_t) = {
        aes_256_cbc,
        aes_256_ctr,
        aes_256_ofb,
        aes_256_cfb,
    };

    const char *aes_function_names[] = {
        "AES-256-CBC",
        "AES-256-CTR",
        "AES-256-OFB",
        "AES-256-CFB"
    };
    size_t aes_num_functions = sizeof(aes_encryption_functions) / sizeof(aes_encryption_functions[0]);



    for (size_t i = 0; i < aes_num_functions; i++) {
        int L = 1025;
        unsigned char *plaintext = random_string_generator(L);
        size_t plaintext_len = strlen((const char *)plaintext);
        unsigned char *key =random_string_generator(32);
        unsigned char *IV = random_string_generator(16);
        size_t key_len = 32;
        size_t IV_len = 16;

        init();
        float time_spent = (cpu_time(aes_encryption_functions[i], plaintext, key, IV, plaintext_len, key_len, IV_len))/1000;
        float cycles = cpu_cycles(aes_encryption_functions[i], plaintext, key, IV, plaintext_len, key_len, IV_len);
        float thr = throughput(aes_encryption_functions[i], plaintext, key, IV, plaintext_len, key_len, IV_len);
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
