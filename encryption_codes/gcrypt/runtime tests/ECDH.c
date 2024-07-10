#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define ECC_CURVE_NAME "prime256v1" // Use "prime256v1" for NIST P-256 curve

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

void generate_ecdh_keypair(EC_KEY **pub_key, EC_KEY **priv_key) {
    EC_KEY *ecdh_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh_key)
        handle_openssl_error();

    if (!EC_KEY_generate_key(ecdh_key))
        handle_openssl_error();

    *priv_key = ecdh_key;
    *pub_key = EC_KEY_new();
    if (!*pub_key || !EC_KEY_copy(*pub_key, ecdh_key))
        handle_openssl_error();

    EC_KEY_set_asn1_flag(*pub_key, OPENSSL_EC_NAMED_CURVE);
}

void compute_ecdh_shared_secret(const EC_KEY *pub_key, const EC_KEY *priv_key, unsigned char *shared_secret, size_t *shared_secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx)
        handle_openssl_error();

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, EC_KEY_get0_public_key(pub_key)) <= 0 ||
        EVP_PKEY_derive(ctx, NULL, shared_secret_len) <= 0 ||
        EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        handle_openssl_error();
    }

    EVP_PKEY_CTX_free(ctx);
}

int main() {
    EC_KEY *alice_pub_key = NULL, *alice_priv_key = NULL;
    EC_KEY *bob_pub_key = NULL, *bob_priv_key = NULL;

    // Generate key pairs for Alice and Bob
    generate_ecdh_keypair(&alice_pub_key, &alice_priv_key);
    generate_ecdh_keypair(&bob_pub_key, &bob_priv_key);

    // Compute shared secret for Alice
    size_t shared_secret_len = EVP_PKEY_size(EVP_PKEY_new());
    unsigned char *alice_shared_secret = malloc(shared_secret_len);
    if (!alice_shared_secret)
        handle_openssl_error();

    compute_ecdh_shared_secret(bob_pub_key, alice_priv_key, alice_shared_secret, &shared_secret_len);

    // Print or use alice_shared_secret as needed (e.g., as symmetric keys for encryption)
    printf("Alice's shared secret (hexadecimal):\n");
    for (size_t i = 0; i < shared_secret_len; ++i) {
        printf("%02X", alice_shared_secret[i]);
    }
    printf("\n");

    // Clean up
    EC_KEY_free(alice_pub_key);
    EC_KEY_free(alice_priv_key);
    EC_KEY_free(bob_pub_key);
    EC_KEY_free(bob_priv_key);
    free(alice_shared_secret);

    return 0;
}
