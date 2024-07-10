#define _POSIX_C_SOURCE 200809L
#include "../../install/include/gcrypt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "cycle-timings.h"
#include "cpu-usage.h"
#include <sys/random.h>
#include <string.h>


#define KEY_LENGTH 2048
#define HASH_ALGO GCRY_MD_SHA256
#define HASH_LENGTH 256


void handle_error(gcry_error_t err) {
    if (err) {
        fprintf(stderr, "Failure: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
        exit(1);
    }
}

void generate_rsa_keys(gcry_sexp_t *pub_key, gcry_sexp_t *priv_key) {
    gcry_error_t err;
    gcry_sexp_t key_params;

    // Create the key parameters
    const char *key_params_str = "(genkey (rsa (nbits 4:2048)))";
    err = gcry_sexp_build(&key_params, NULL, key_params_str);
    handle_error(err);

    // Generate the key pair
    gcry_sexp_t key_pair;
    err = gcry_pk_genkey(&key_pair, key_params);
    handle_error(err);

    // Get the public and private keys
    *pub_key = gcry_sexp_find_token(key_pair, "public-key", 0);
    *priv_key = gcry_sexp_find_token(key_pair, "private-key", 0);

    gcry_sexp_release(key_params);
    gcry_sexp_release(key_pair);

    if (*pub_key == NULL || *priv_key == NULL) {
        fprintf(stderr, "Failed to extract public or private key\n");
        exit(1);
    }
}


void rsa_sign(gcry_sexp_t priv_key, unsigned char *plaintext, size_t plaintext_len, gcry_sexp_t *signature) {
    gcry_error_t err;
    gcry_sexp_t data_sexp, hash_sexp, sig_sexp;
    gcry_md_hd_t md_handle;
    unsigned char hash_buffer[HASH_LENGTH / 8];

    err = gcry_md_open(&md_handle, HASH_ALGO, 0);
    handle_error(err);
    gcry_md_write(md_handle, plaintext, plaintext_len);
    memcpy(hash_buffer, gcry_md_read(md_handle, HASH_ALGO), HASH_LENGTH / 8);
    gcry_md_close(md_handle);

    // Create the data S-expression
    err = gcry_sexp_build(&data_sexp, NULL, "(data (flags pss) (hash %s %b))",
                          gcry_md_algo_name(HASH_ALGO), HASH_LENGTH / 8, hash_buffer);
    handle_error(err);

    // Sign the data
    err = gcry_pk_sign(&sig_sexp, data_sexp, priv_key);
    if (err) {
        fprintf(stderr, "Failed to sign data: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        gcry_sexp_release(data_sexp);
        exit(1);
    }

    *signature = sig_sexp;

    gcry_sexp_release(data_sexp);
}

int rsa_verify(gcry_sexp_t pub_key, unsigned char *plaintext, size_t plaintext_len, gcry_sexp_t signature) {
    gcry_error_t err;
    gcry_sexp_t data_sexp;
    gcry_md_hd_t md_handle;
    unsigned char hash_buffer[HASH_LENGTH / 8];

    err = gcry_md_open(&md_handle, HASH_ALGO, 0);
    handle_error(err);
    gcry_md_write(md_handle, plaintext, plaintext_len);
    memcpy(hash_buffer, gcry_md_read(md_handle, HASH_ALGO), HASH_LENGTH / 8);
    gcry_md_close(md_handle);

    // Create the data S-expression
    err = gcry_sexp_build(&data_sexp, NULL, "(data (flags pss) (hash %s %b))",
                            gcry_md_algo_name(HASH_ALGO), HASH_LENGTH / 8, hash_buffer);
    handle_error(err);

    // Verify the signature
    err = gcry_pk_verify(signature, data_sexp, pub_key);

    gcry_sexp_release(data_sexp);

    return err == 0;  // Return 1 if successful, 0 otherwise
}

int rsassa(unsigned char *plaintext, size_t plaintext_len) {
    // Initialize the library
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        exit(1);
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Generate RSA keys
    gcry_sexp_t pub_key = NULL, priv_key = NULL;
    generate_rsa_keys(&pub_key, &priv_key);


    // Sign the data
    gcry_sexp_t signature = NULL;
    rsa_sign(priv_key, plaintext, plaintext_len, &signature);

    // Verify the signature
    int is_valid = rsa_verify(pub_key, (unsigned char *)plaintext, plaintext_len, signature);

    // Print the result
    if (!is_valid) {
        printf("Signature is invalid.\n");
    } 

    // Cleanup
    gcry_sexp_release(signature);
    gcry_sexp_release(pub_key);
    gcry_sexp_release(priv_key);

    return 0;
}

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*, size_t), unsigned char *plaintext, size_t plaintext_len)
{
    float time_spent;
    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    //uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        int x = (*f)(plaintext, plaintext_len);

        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        const uint64_t ns = (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);

        cycles[i] = ns;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    time_spent = (float)(cycles[NUM_TIMINGS / 2])/ 1000000000.0;
    free(cycles);


    return time_spent;
}


//This measures CPU cycles for encryption process
float cpu_cycles(int (*f)(unsigned char*, size_t), unsigned char *plaintext, size_t plaintext_len)
{

    //Measure the overhead of timing

    uint64_t timing_overhead;
    timing_overhead = measure_overhead();


    //Compute the length of processed data 

    int byte_length_of_processed_data = plaintext_len;
    float rate;

    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        temp = start_timer();

        int x = (*f)(plaintext, plaintext_len);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)(unsigned char*, size_t), unsigned char *plaintext, size_t plaintext_len)
{
    int byte_length_of_processed_data = plaintext_len;
    float time = cpu_time(f, plaintext, plaintext_len);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}

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



//This measures execution runtime
int main()
{   
     
    int L = (KEY_LENGTH/8) - (2*HASH_LENGTH/8) -1;

    unsigned char *plaintext = random_string_generator(1025);
    size_t plaintext_len = strlen((unsigned char* )plaintext);

    init();
    float time_spent = cpu_time(rsassa, plaintext, plaintext_len);
    double cpu_usage = getCurrentValue();
    float rate = cpu_cycles(rsassa, plaintext,  plaintext_len);
    float Throughput = throughput(rsassa, plaintext,  plaintext_len);
    
    printf("RSA Mode: RSASSA-PSS\n");
    printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
    printf("Runtime: %f seconds\n", time_spent);
    printf("Throughput: %f Bytes/second\n", Throughput);
    printf("CPU Usage: %.2f%% \n", cpu_usage);
    printf("Length: %ld\n", plaintext_len);
    printf("\n");
     
    return 0; 
}
