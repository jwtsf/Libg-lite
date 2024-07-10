#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#define ECC_CURVE "NIST P-256"
#define MESSAGE "Hello, ECDSA!"
int main() {
    gcry_error_t err;
    gcry_sexp_t pubkey, privkey, sig;
    const char *message = MESSAGE;

    // Initialize the library
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 2;
    }

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Generate EC key pair
    generate_ec_keypair(&pubkey, &privkey, ECC_CURVE);

    // Sign the message
    sig = sign_message(message, privkey);

    // Print the signature
    print_signature(sig);

    // Verify the signature
    int verified = verify_signature(message, sig, pubkey);

    if (verified) {
        printf("Signature verification succeeded\n");
    } else {
        printf("Signature verification failed\n");
    }

    // Clean up
    gcry_sexp_release(pubkey);
    gcry_sexp_release(privkey);
    gcry_sexp_release(sig);

    gcry_check_version(NULL);

    return 0;
}