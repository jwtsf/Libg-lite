#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>


int main() {
    const unsigned char *plaintext = (const unsigned char *)"This is a test message.";

    // Test SHA-512
    printf("Testing SHA-512...\n");
    unsigned char hash512[64];
    if (sha512(plaintext, hash512) == 0) {
        printf("Successful\n");
    } else {
        printf("SHA-512 hashing failed.\n");
    }

    // Test SHA-384
    printf("Testing SHA-384...\n");
    unsigned char hash384[48];
    if (sha384(plaintext, hash384) == 0) {
        printf("Successful\n");
    } else {
        printf("SHA-384 hashing failed.\n");
    }

    // Test SHA-256
    printf("Testing SHA-256...\n");
    unsigned char hash256[32];
    if (sha256(plaintext, hash256) == 0) {
        printf("Successful\n");
    } else {
        printf("SHA-256 hashing failed.\n");
    }

    return 0;
}
