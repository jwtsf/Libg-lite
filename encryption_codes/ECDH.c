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

#define ECC_CURVE "NIST P-256"
#define AES_KEY_SIZE 32 // AES-256 key size in bytes
#define MAC_KEY_SIZE 32 // HMAC-SHA256 key size in bytes
#define AES_BLOCK_SIZE 16 // AES block size in bytes
#define HMAC_SIZE 32 // HMAC-SHA256 output size in bytes
#define KDF_OUTPUT_SIZE 32

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

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void generate_ec_keypair(gcry_sexp_t *pub_key, gcry_sexp_t *priv_key) {
    gcry_error_t err;
    gcry_sexp_t key_params;

    // Create the key parameters
    const char *key_params_str = "(genkey (ecc (curve \"nistp256\")))";
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

gcry_mpi_t compute_ecdh_shared_secret(gcry_sexp_t pub_key, gcry_sexp_t priv_key) {
    gcry_error_t err;
    gcry_sexp_t shared_secret = NULL;
    gcry_sexp_t value = NULL;
    gcry_mpi_t shared_secret_mpi = NULL;
    // Create a temporary S-expression for the ECDH operation
    gcry_sexp_t ecdh_params;
    const char *ecdh_params_str = "(ecc-point (public-key %S) (private-key %S))";
    err = gcry_sexp_build(&ecdh_params, NULL, ecdh_params_str, pub_key, priv_key);
    handle_error(err);

    // Perform the ECDH operation
    err = gcry_pk_encrypt(&shared_secret, ecdh_params, pub_key);
    handle_error(err);

    // Get the ciphertext
    value = gcry_sexp_find_token(shared_secret, "s", 0);
    if (!value) {
        fprintf(stderr, "Failed to find value in encrypted data\n");
        //gcry_sexp_dump(enc_data);
        exit(1);
    }

    shared_secret_mpi = gcry_sexp_nth_mpi(value, 1, GCRYMPI_FMT_USG);
    if (!shared_secret_mpi) {
        fprintf(stderr, "Failed to get MPI from encrypted value\n");
        exit(1);
    }
    // Extract the MPI from the shared secret


    gcry_sexp_release(shared_secret);

    return shared_secret_mpi;
}

void stretch_shared_secret(gcry_mpi_t shared_secret_mpi, unsigned char *kdf_output) {
    gcry_error_t err;
    const unsigned char *salt = NULL; // Salt can be NULL for PBKDF2

    // Convert the shared_secret_mpi to a byte array
    unsigned char *shared_secret_bytes;
    // Check if shared_secret_mpi is valid
    if (!shared_secret_mpi) {
        fprintf(stderr, "shared_secret_mpi is NULL\n");
        return;
    }
    size_t shared_secret_len = (gcry_mpi_get_nbits(shared_secret_mpi) + 7) / 8; // Calculate the byte length

    shared_secret_bytes = malloc(shared_secret_len);
    if (!shared_secret_bytes) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    err = gcry_mpi_print(GCRYMPI_FMT_USG, shared_secret_bytes, shared_secret_len, NULL, shared_secret_mpi);
    handle_error(err);


    // Derive two keys using PBKDF2 from the shared secret
    err = gcry_kdf_derive(shared_secret_bytes,
                          shared_secret_len, // Use the byte length of the shared secret
                          GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
                          "abc", 3, // Use the salt
                          1, // Iteration count
                          KDF_OUTPUT_SIZE,
                          kdf_output);
    if (err) {
        fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        free(shared_secret_bytes);
        return;
    }

    free(shared_secret_bytes);
}


int ecdh_secret_generation() {
    gcry_error_t err;
    gcry_sexp_t pubkey_alice = NULL, privkey_alice = NULL;
    gcry_sexp_t pubkey_bob = NULL, privkey_bob = NULL;
    gcry_sexp_t eph_pubkey = NULL, eph_privkey = NULL;
    gcry_mpi_t shared_secret_mpi = NULL;
    unsigned char kdf_output[KDF_OUTPUT_SIZE];

    // Initialize the library
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 2;
    }

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Generate EC key pair for Alice and Bob
    generate_ec_keypair(&pubkey_alice, &privkey_alice);
    generate_ec_keypair(&pubkey_bob, &privkey_bob);

    // Generate ephemeral key pair for Alice
    generate_ec_keypair(&eph_pubkey, &eph_privkey);

    // Compute ECDH shared secret between Alice's ephemeral private key and Bob's public key
    shared_secret_mpi = compute_ecdh_shared_secret(pubkey_bob, eph_privkey);

    // Stretch the shared secret using KDF to derive two keys
    stretch_shared_secret(shared_secret_mpi, kdf_output);

    // Print or use kdf_output as needed (e.g., as symmetric keys for encryption)
    //printf("Derived Key (hexadecimal):\n");
    //print_hex(kdf_output, KDF_OUTPUT_SIZE);
    // Clean up
    gcry_mpi_release(shared_secret_mpi);
    gcry_sexp_release(pubkey_alice);
    gcry_sexp_release(privkey_alice);
    gcry_sexp_release(pubkey_bob);
    gcry_sexp_release(privkey_bob);
    gcry_sexp_release(eph_pubkey);
    gcry_sexp_release(eph_privkey);

    gcry_check_version(NULL);

    return 0;
}

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)())
{
    float time_spent;
    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    //uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        int x = (*f)();

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
float cpu_cycles(int (*f)())
{

    //Measure the overhead of timing

    uint64_t timing_overhead;
    timing_overhead = measure_overhead();
    printf("Timing overhead: %lu clock cycles\n", timing_overhead);


    //Compute the length of processed data 

    int byte_length_of_processed_data = KDF_OUTPUT_SIZE;
    float rate;

    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        temp = start_timer();

        int x = (*f)();

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)())
{
    int byte_length_of_processed_data = KDF_OUTPUT_SIZE;
    float time = cpu_time(f);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}

//This measures execution runtime
int main()
{  

    init();
    float time_spent = cpu_time(ecdh_secret_generation);
    float rate = cpu_cycles(ecdh_secret_generation);
    float Throughput = throughput(ecdh_secret_generation);
    double cpu_usage = getCurrentValue();

    //printf("Runtime: %f seconds\n", time_spent);
    printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
    printf("Runtime: %f seconds\n", time_spent);
    printf("Throughput: %f Bytes/second\n", Throughput);
    printf("CPU Usage: %.2f%% \n", cpu_usage);
    printf("Length: %d", KDF_OUTPUT_SIZE);
    printf("\n");


}