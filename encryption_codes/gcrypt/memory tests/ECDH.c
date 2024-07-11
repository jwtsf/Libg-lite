#include "compiled.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

int main() {
    unsigned char *curve_name = "nistp256";  // Example curve name, replace with your desired curve

    // Test ECDH secret generation
    int result = ecdh_secret_generation(curve_name);
    if (result != 0) {
        fprintf(stderr, "ECDH secret generation failed with error code: %d\n", result);
        return 1;
    }

    printf("ECDH secret generation successful!\n");

    return 0;
}