#ifndef COMPILED_H
#define COMPILED_H
#include "../../../install/include/gcrypt.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>


void handle_error(gcry_error_t err) {
    if (err) {
        fprintf(stderr, "Failure: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
        exit(1);
    }
}

//========================================//
//-- PKCS7 Padding -----------------------//
//========================================//

unsigned char* pad(const unsigned char* input, size_t input_len, size_t* padded_len, int block_size) {
    size_t pad_len = block_size - (input_len % block_size);
    *padded_len = input_len + pad_len;
    unsigned char* padded_input = (unsigned char*)malloc(*padded_len);
    if (!padded_input) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    memcpy(padded_input, input, input_len);
    memset(padded_input + input_len, pad_len, pad_len);
    return padded_input;
}

// Remove PKCS7 padding from the decrypted text
size_t unpad(unsigned char* padded_input, size_t padded_len) {
    size_t pad_len = padded_input[padded_len - 1];
    return padded_len - pad_len;
}

//========================================//
//-- SHA ---------------------------------//
//========================================//

int sha512(const unsigned char* plaintext, unsigned char* hash) {

    size_t plaintext_len = strlen((const char *)plaintext);
    // Ensure the library has been initialized
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 1;
    }

    // Initialize the library (optional since version 1.6)
    gcry_error_t err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err) {
        fprintf(stderr, "Failed to initialize libgcrypt: %s\n", gcry_strerror(err));
        return 1;
    }

    // Message to be hashed
    //unsigned char hash[64]; // SHA-256 outputs 32 bytes (256 bits)

    // Hash the message
    gcry_md_hash_buffer(GCRY_MD_SHA512, hash, plaintext, plaintext_len);


    return 0;
}

int sha384(const unsigned char* plaintext, unsigned char* hash) {

    size_t plaintext_len = strlen((const char *)plaintext);
    // Ensure the library has been initialized
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 1;
    }

    // Initialize the library (optional since version 1.6)
    gcry_error_t err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err) {
        fprintf(stderr, "Failed to initialize libgcrypt: %s\n", gcry_strerror(err));
        return 1;
    }

    // Message to be hashed
    //unsigned char hash[64]; // SHA-256 outputs 32 bytes (256 bits)

    // Hash the message
    gcry_md_hash_buffer(GCRY_MD_SHA384, hash, plaintext, plaintext_len);


    return 0;
}

int sha256(const unsigned char* plaintext, unsigned char* hash) {

    size_t plaintext_len = strlen((const char *)plaintext);
    // Ensure the library has been initialized
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 1;
    }

    // Initialize the library (optional since version 1.6)
    gcry_error_t err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err) {
        fprintf(stderr, "Failed to initialize libgcrypt: %s\n", gcry_strerror(err));
        return 1;
    }

    // Message to be hashed
    //unsigned char hash[64]; // SHA-256 outputs 32 bytes (256 bits)

    // Hash the message
    gcry_md_hash_buffer(GCRY_MD_SHA256, hash, plaintext, plaintext_len);


    return 0;
}

//========================================//
//-- AES ---------------------------------//
//========================================//


//========= Encryption ========//


int aes_generic_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len, int mode, int cipher, unsigned char *ciphertext) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;
    

    // Initialize Libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "Libgcrypt version mismatch\n");
        return 1;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Open cipher handle
    err = gcry_cipher_open(&handle, cipher, mode, 0);
    handle_error(err);
    // Set the key
    err = gcry_cipher_setkey(handle, key, key_len);
    handle_error(err);

    // Set the IV (initialization vector)
    err = gcry_cipher_setiv(handle, IV, IV_len);
    handle_error(err);


    size_t padded_len = 0;
    unsigned char *padded_plaintext = pad(plaintext, plaintext_len, &padded_len, 16);
    // Encrypt the plaintext
    err = gcry_cipher_encrypt(handle, ciphertext, padded_len, padded_plaintext, padded_len);
    handle_error(err);

    // Clean up
    gcry_cipher_close(handle);
    return 0;
}


int aes_cbc_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext) {
    return aes_generic_encrypt(plaintext, key, IV, plaintext_len, key_len, IV_len, GCRY_CIPHER_MODE_CBC, cipher, ciphertext);
}

int aes_cfb_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext) {
    return aes_generic_encrypt(plaintext, key, IV, plaintext_len, key_len, IV_len, GCRY_CIPHER_MODE_CFB, cipher, ciphertext);
}

int aes_ofb_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext) {
    return aes_generic_encrypt(plaintext, key, IV, plaintext_len, key_len, IV_len, GCRY_CIPHER_MODE_OFB, cipher, ciphertext);
}


int aes_ctr_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                 size_t plaintext_len, size_t key_len, size_t IV_len,  int cipher, unsigned char *ciphertext)
{
        gcry_cipher_hd_t handle;
    gcry_error_t err;

    // Open cipher handle
    err = gcry_cipher_open(&handle, cipher, GCRY_CIPHER_MODE_CTR, 0);
    handle_error(err);

    // Set the key
    err = gcry_cipher_setkey(handle, key, key_len);
    handle_error(err);

    // Set the IV (counter)
    err = gcry_cipher_setctr(handle, IV, IV_len);
    handle_error(err);

    // Encrypt the plaintext
    err = gcry_cipher_encrypt(handle, ciphertext, plaintext_len, plaintext, plaintext_len);
    handle_error(err);

    // Clean up
    gcry_cipher_close(handle);
    return 0;
}

//========= Decryption ========//

int aes_generic_decrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                 size_t plaintext_len, size_t key_len, size_t IV_len,  int cipher, int mode, const unsigned char *ciphertext, unsigned char* decrypted) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;
    

    // Initialize Libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "Libgcrypt version mismatch\n");
        return 1;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);


    // Open cipher handle
    err = gcry_cipher_open(&handle, cipher, mode, 0);
    handle_error(err);

    // Set the key
    err = gcry_cipher_setkey(handle, key, key_len);
    handle_error(err);

    // Set the IV (initialization vector)
    err = gcry_cipher_setiv(handle, IV, IV_len);
    handle_error(err);

    // Decrypt the ciphertext
    err = gcry_cipher_decrypt(handle, decrypted, plaintext_len, ciphertext, plaintext_len);
    handle_error(err);

    // Clean up
    gcry_cipher_close(handle);

    return 0;
}

int aes_cbc_decrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext, unsigned char *decrypted) {
    return aes_generic_decrypt(plaintext, key, IV, plaintext_len, key_len, IV_len, cipher, GCRY_CIPHER_MODE_CBC, ciphertext, decrypted);
}

int aes_cfb_decrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext, unsigned char *decrypted) {
    return aes_generic_decrypt(plaintext, key, IV, plaintext_len, key_len, IV_len, cipher, GCRY_CIPHER_MODE_CFB, ciphertext, decrypted);
}

int aes_ofb_decrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext, unsigned char *decrypted) {
    return aes_generic_decrypt(plaintext, key, IV, plaintext_len, key_len, IV_len, cipher, GCRY_CIPHER_MODE_OFB, ciphertext, decrypted);
}

int aes_ctr_decrypt(unsigned char *plaintext, unsigned char *key, unsigned char *IV,
                 size_t plaintext_len, size_t key_len, size_t IV_len, const unsigned char *ciphertext, int cipher, unsigned char* decrypted) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;

    // Open cipher handle
    err = gcry_cipher_open(&handle, cipher, GCRY_CIPHER_MODE_CTR, 0);
    handle_error(err);

    // Set the key
    err = gcry_cipher_setkey(handle, key,key_len);
    handle_error(err);

    // Set the IV (counter)
    err = gcry_cipher_setctr(handle, IV, IV_len);
    handle_error(err);

    // Decrypt the ciphertext
    err = gcry_cipher_decrypt(handle, decrypted, plaintext_len, ciphertext, plaintext_len);
    handle_error(err);

    // Clean up
    gcry_cipher_close(handle);

    return 1;
}

//========================================//
//-- RSA ---------------------------------//
//========================================//

//#define KEY_LENGTH 2048
#define HASH_ALGO GCRY_MD_SHA256
#define HASH_LENGTH 256

void generate_rsa_keys(gcry_sexp_t *pub_key, gcry_sexp_t *priv_key, int key_length) {
    gcry_error_t err;
    gcry_sexp_t key_params;

    // Create the key parameters
    char key_params_str[100]; // Ensure the buffer is large enough
    sprintf(key_params_str, "(genkey (rsa (nbits 4:%d)))", key_length);
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
    *ciphertext = (unsigned char *)malloc(*ciphertext_len);
    if (*ciphertext == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // Cleanup
    gcry_sexp_release(data);
    gcry_sexp_release(enc_data);
    gcry_sexp_release(value);
    gcry_mpi_release(enc_mpi);
}

void rsa_oaep_encrypt(gcry_sexp_t pub_key, unsigned char *plaintext, 
                    size_t plaintext_len, unsigned char **ciphertext, size_t *ciphertext_len) {
    return rsa_encrypt_generic(pub_key, plaintext, plaintext_len, ciphertext, ciphertext_len, "oaep");
}

void rsa_pkcs1_encrypt(gcry_sexp_t pub_key, unsigned char *plaintext, 
                    size_t plaintext_len, unsigned char **ciphertext, size_t *ciphertext_len) {
    return rsa_encrypt_generic(pub_key, plaintext, plaintext_len, ciphertext, ciphertext_len, "pkcs1");
}

//========================================//
//-- RSASSA ------------------------------//
//========================================//
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

//========================================//
//-- ECDH --------------------------------//
//========================================//
//#define ECC_CURVE "nistp256"
#define KDF_OUTPUT_SIZE 32


void generate_ec_keypair(gcry_sexp_t *pub_key, gcry_sexp_t *priv_key, const char *curve_name) {
    gcry_error_t err;
    gcry_sexp_t key_params;

    char key_params_str[100]; // Ensure the buffer is large enough

    // Construct the key parameters string
    sprintf(key_params_str, "(genkey (ecc (curve \"%s\")))", curve_name);
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

    shared_secret_bytes = (unsigned char*)malloc(shared_secret_len);
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
        // Print the shared secret
    printf("Generated Shared Secret (hex): ");
    for (size_t i = 0; i < shared_secret_len; ++i) {
        printf("%02X", shared_secret_bytes[i]);
    }
    printf("\n");

    free(shared_secret_bytes);
}

int ecdh_secret_generation(unsigned char* curve_name) {
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
    generate_ec_keypair(&pubkey_alice, &privkey_alice, curve_name);
    generate_ec_keypair(&pubkey_bob, &privkey_bob, curve_name);

    // Generate ephemeral key pair for Alice
    generate_ec_keypair(&eph_pubkey, &eph_privkey, curve_name);

    // Compute ECDH shared secret between Alice's ephemeral private key and Bob's public key
    shared_secret_mpi = compute_ecdh_shared_secret(pubkey_bob, eph_privkey);

    // Stretch the shared secret using KDF to derive two keys
    stretch_shared_secret(shared_secret_mpi, kdf_output);

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

//========================================//
//-- ECDSA -------------------------------//
//========================================//
gcry_sexp_t sign_message(const char *message, gcry_sexp_t priv_key)
{
    gcry_error_t err;
    gcry_sexp_t sig, data;

    err = gcry_sexp_build(&data, NULL, "(data (flags raw)(value %s))", message);
    handle_error(err);

    err = gcry_pk_sign(&sig, data, priv_key);
    handle_error(err);

    gcry_sexp_release(data);
    
    return sig;
}

int verify_signature(const char *message,gcry_sexp_t sig, gcry_sexp_t pub_key)
{
    gcry_error_t err;
    gcry_sexp_t data;

    err = gcry_sexp_build(&data, NULL, "(data (flags raw)(value %s))", message);
    handle_error(err);

    err = gcry_pk_verify(sig, data, pub_key);
    gcry_sexp_release(data);

    if (err)
    {
        //printf("Verification failed\n");
        return 0;
    } else 
    {
        //printf("Verification succeeded\n");
        return 1;
    }

}

void print_signature(gcry_sexp_t sig) {
    gcry_sexp_t r, s;
    r = gcry_sexp_find_token(sig, "r", 0);
    s = gcry_sexp_find_token(sig, "s", 0);

    if (r && s) {
        gcry_mpi_t r_mpi, s_mpi;
        r_mpi = gcry_sexp_nth_mpi(r, 1, GCRYMPI_FMT_USG);
        s_mpi = gcry_sexp_nth_mpi(s, 1, GCRYMPI_FMT_USG);

        // Print the r value
        unsigned char *r_buffer = NULL;
        size_t r_buf_len = 0;
        gcry_mpi_aprint(GCRYMPI_FMT_HEX, &r_buffer, &r_buf_len, r_mpi);
        printf("Signature (r): %s\n", r_buffer);
        gcry_free(r_buffer);

        // Print the s value
        unsigned char *s_buffer = NULL;
        size_t s_buf_len = 0;
        gcry_mpi_aprint(GCRYMPI_FMT_HEX, &s_buffer, &s_buf_len, s_mpi);
        printf("Signature (s): %s\n", s_buffer);
        gcry_free(s_buffer);

        gcry_mpi_release(r_mpi);
        gcry_mpi_release(s_mpi);
    }


    gcry_sexp_release(r);
    gcry_sexp_release(s);
}

//========================================//
//-- SM4 ---------------------------------//
//========================================//

void sm4_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, size_t plaintext_len, size_t padded_len, size_t IV_len, size_t key_len, int cipher, int mode, unsigned char *ciphertext) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;


    // Initialize the library
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return;
    }

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Open cipher handle
    err = gcry_cipher_open(&handle, cipher, mode, 0);
    handle_error(err);

    // Set the key
    err = gcry_cipher_setkey(handle, key, key_len);
    handle_error(err);

    // Set the IV
    err = gcry_cipher_setiv(handle, iv, IV_len);
    handle_error(err);

    // Add padding to the plaintext
    unsigned char* padded_plaintext = pad((const unsigned char*)plaintext, plaintext_len, &padded_len, 16);

    // Encrypt the padded plaintext
    err = gcry_cipher_encrypt(handle, ciphertext, padded_len, padded_plaintext, padded_len);
    handle_error(err);
}

void sm4_decrypt(unsigned char *iv, unsigned char *key, size_t padded_len, size_t IV_len, size_t key_len, int cipher, int mode, unsigned char *ciphertext, unsigned char* decrypted)
{
    gcry_cipher_hd_t handle;
    gcry_error_t err;
        // Initialize Libgcrypt
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);


    err = gcry_cipher_open(&handle, cipher, mode, 0);
    handle_error(err);

    // Set the key
    err = gcry_cipher_setkey(handle, key, key_len);
    handle_error(err);

    // Set the IV
    err = gcry_cipher_setiv(handle, iv, IV_len);
    handle_error(err);

    // Decrypt the ciphertext
    err = gcry_cipher_decrypt(handle, decrypted, padded_len, ciphertext, padded_len);
    handle_error(err);

    
}

#endif