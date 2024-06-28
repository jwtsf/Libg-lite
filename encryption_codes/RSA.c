#define _POSIX_C_SOURCE 200809L
#include "../install/include/gcrypt.h"
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

// Function to print S-expression
void print_sexp(const char *label, gcry_sexp_t sexp) {
    char *buffer;
    size_t length = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buffer = malloc(length);
    if (buffer) {
        gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buffer, length);
        printf("%s: %s\n", label, buffer);
        free(buffer);
    } else {
        fprintf(stderr, "Memory allocation failed\n");
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

void rsa_encrypt_generic(gcry_sexp_t pub_key, unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext, size_t *ciphertext_len, unsigned char *mode) {
    gcry_error_t err;
    gcry_sexp_t data = NULL, enc_data = NULL;
    gcry_sexp_t value = NULL;
    gcry_mpi_t enc_mpi = NULL;

    // Build the data sexp
    err = gcry_sexp_build(&data, NULL, "(data (flags %s) (hash-algo %s) (value %b))",
                          mode, gcry_md_algo_name(HASH_ALGO),
                          plaintext_len, plaintext);
    handle_error(err);

    // Encrypt the data
    err = gcry_pk_encrypt(&enc_data, data, pub_key);
    handle_error(err);

    // Get the ciphertext
    value = gcry_sexp_find_token(enc_data, "a", 0);
    if (!value) {
        fprintf(stderr, "Failed to find value in encrypted data\n");
        //gcry_sexp_dump(enc_data);
        exit(1);
    }

    enc_mpi = gcry_sexp_nth_mpi(value, 1, GCRYMPI_FMT_USG);
    if (!enc_mpi) {
        fprintf(stderr, "Failed to get MPI from encrypted value\n");
        exit(1);
    }

    *ciphertext_len = (gcry_mpi_get_nbits(enc_mpi) + 7) / 8;  // Calculate the byte length
    *ciphertext = malloc(*ciphertext_len);
    if (*ciphertext == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    err = gcry_mpi_print(GCRYMPI_FMT_USG, *ciphertext, *ciphertext_len, NULL, enc_mpi);
    handle_error(err);

    // Cleanup
    gcry_sexp_release(data);
    gcry_sexp_release(enc_data);
    gcry_sexp_release(value);
    gcry_mpi_release(enc_mpi);
}

void rsa_encrypt_oaep(gcry_sexp_t pub_key, unsigned char *plaintext, 
                    size_t plaintext_len, unsigned char **ciphertext, size_t *ciphertext_len) {
    return rsa_encrypt_generic(pub_key, plaintext, plaintext_len, ciphertext, ciphertext_len, "oaep");
}

void rsa_encrypt_pkcs1(gcry_sexp_t pub_key, unsigned char *plaintext, 
                    size_t plaintext_len, unsigned char **ciphertext, size_t *ciphertext_len) {
    return rsa_encrypt_generic(pub_key, plaintext, plaintext_len, ciphertext, ciphertext_len, "pkcs1");
}

int rsa2048(unsigned char* plaintext, int mode) {
    gcry_error_t err;

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
    // Print the public and private keys (for verification)
    //print_sexp("Public key", pub_key);
    //print_sexp("Private key", priv_key);
    // The plaintext to be encrypted
    size_t plaintext_len = strlen(plaintext);

    // Encrypt the plaintext
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    if (mode==0) {
        rsa_encrypt_oaep(pub_key, plaintext, plaintext_len, &ciphertext, &ciphertext_len);
    } 
    else if (mode==1) {
        rsa_encrypt_pkcs1(pub_key, plaintext, plaintext_len, &ciphertext, &ciphertext_len);
    }


    // Cleanup
    free(ciphertext);
    gcry_sexp_release(pub_key);
    gcry_sexp_release(priv_key);

    return 0;
}

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*, int), unsigned char *plaintext, size_t plaintext_len, int mode)
{
    float time_spent;
    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    //uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        int x = (*f)(plaintext, mode);

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
float cpu_cycles(int (*f)(unsigned char*, int), unsigned char *plaintext, size_t plaintext_len, int mode)
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

        int x = (*f)(plaintext, mode);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)(unsigned char*, int), unsigned char *plaintext, size_t plaintext_len, int mode)
{
    int byte_length_of_processed_data = plaintext_len;
    float time = cpu_time(f, plaintext, plaintext_len, mode);
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
    const char *rsa_function_names[] = {
        "RSA-2048-OAEP",
        "RSA-2048-PKCS#1",
    };

    size_t rsa_num_functions = sizeof(rsa_function_names) / sizeof(rsa_function_names[0]);

    for (int i = 0; i < (int)rsa_num_functions; i++) {
        
        
        int L = (KEY_LENGTH/8) - (2*HASH_LENGTH/8) -1;

        unsigned char *plaintext = random_string_generator(L);
        size_t plaintext_len = strlen((unsigned char* )plaintext);

        init();
        float time_spent = cpu_time(rsa2048, plaintext, plaintext_len, i);
        double cpu_usage = getCurrentValue();
        float rate = cpu_cycles(rsa2048, plaintext,  plaintext_len, i);
        float Throughput = throughput(rsa2048, plaintext,  plaintext_len, i);
        
        printf("RSA Mode: %s\n", rsa_function_names[i]);
        printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
        printf("Runtime: %f seconds\n", time_spent);
        printf("Throughput: %f Bytes/second\n", Throughput);
        printf("CPU Usage: %.2f%% \n", cpu_usage);
        printf("Length: %ld\n", plaintext_len);
        printf("\n");
     
    }


    return 0; 
}
