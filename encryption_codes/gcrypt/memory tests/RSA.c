#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>


void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    gcry_sexp_t pub_key = NULL, priv_key = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    const unsigned char *plaintext = (const unsigned char *)"This is a test message.";
    const char *mode = "pkcs1";

    // Initialize Libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "Libgcrypt version mismatch\n");
        return 1;
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Generate RSA key pair
    printf("Generating RSA keys...\n");
    generate_rsa_keys(&pub_key, &priv_key, 2048);
    printf("RSA keys generated.\n");

    // Encrypt the plaintext
    printf("Encrypting plaintext...\n");
    rsa_encrypt_generic(pub_key, (unsigned char *)plaintext, strlen((const char *)plaintext), &ciphertext, &ciphertext_len, (unsigned char *)mode);
    printf("Encryption complete.\n");

    // Print the ciphertext
    printf("Ciphertext: ");
    print_hex(ciphertext, ciphertext_len);

    // Clean up
    gcry_sexp_release(pub_key);
    gcry_sexp_release(priv_key);
    free(ciphertext);

    return 0;
}
