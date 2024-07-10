#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>



int main() {
    gcry_sexp_t pub_key = NULL, priv_key = NULL, signature = NULL;
    const unsigned char *plaintext = (const unsigned char *)"This is a test message.";
    size_t plaintext_len = strlen((const char *)plaintext);
    const char *mode = "oaep";

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

    // Sign the plaintext
    rsa_sign(priv_key, (unsigned char *)plaintext, plaintext_len, &signature);


    // Verify the signature
    printf("Verifying signature...\n");
    int verify_result = rsa_verify(pub_key, (unsigned char *)plaintext, plaintext_len, signature);
    if (verify_result) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
    }

    // Clean up
    gcry_sexp_release(pub_key);
    gcry_sexp_release(priv_key);
    gcry_sexp_release(signature);

    return 0;
}
