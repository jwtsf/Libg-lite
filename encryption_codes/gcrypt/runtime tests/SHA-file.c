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

unsigned char* file_to_buffer(const char* filename,size_t* padded_size)
{
    FILE *fp = fopen(filename, "rb");
    if (fp != NULL)
    {
        if (fseek(fp, 0L, SEEK_END)!=0)
        {
            return NULL;
        }

        long int size = ftell(fp);
        

        if (fseek(fp, 0L, SEEK_SET) !=0)
        {
            return NULL;
        }
        *padded_size = (size + 16) & ~15;
        unsigned char* buffer = malloc(*padded_size);

        if (!buffer) 
        {
            perror("Memory allocation failed");
            fclose(fp);
            return NULL;
        }

        size_t newLen = fread(buffer, sizeof(unsigned char), size, fp);
        if ( ferror( fp ) != 0 ) {
            fputs("Error reading file", stderr);
            free(buffer);
            fclose(fp);
            return NULL;
        } 
            // Pad the buffer with zeroes if necessary
        if (newLen < *padded_size)
        {
            for (size_t i = newLen; i < *padded_size; ++i)
            {
                buffer[i] = 0;
            }
            
        }
        buffer[*padded_size-1] = '\0';


        fclose(fp);

        return buffer;
    }
}


int msg_hashing(unsigned char* plaintext) {

    size_t plaintext_len = strlen((unsigned char* )plaintext);
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
    unsigned char hash[64]; // SHA-256 outputs 32 bytes (256 bits)

    // Hash the message
    gcry_md_hash_buffer(GCRY_MD_SHA512, hash, plaintext, plaintext_len);


    return 0;
}

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*), unsigned char *plaintext, size_t plaintext_len)
{
    float time_spent;
    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    //uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        int x = (*f)(plaintext);

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
float cpu_cycles(int (*f)(unsigned char*), unsigned char *plaintext, size_t plaintext_len)
{

    //Measure the overhead of timing

    uint64_t timing_overhead;
    timing_overhead = measure_overhead();
    printf("Timing overhead: %lu clock cycles\n", timing_overhead);


    //Compute the length of processed data 

    int byte_length_of_processed_data = plaintext_len;
    float rate;

    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        temp = start_timer();

        int x = (*f)(plaintext);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)(unsigned char* ), unsigned char *plaintext, size_t plaintext_len)
{
    int byte_length_of_processed_data = plaintext_len;
    float time = cpu_time(f, plaintext, plaintext_len);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}

//return random character

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
    int L = 1024;
    size_t padded_size;
    unsigned char *plaintext = file_to_buffer("sample.txt", &padded_size);

    size_t plaintext_len = strlen((const char *)plaintext);

    init();
    float time_spent = 1000000*cpu_time(msg_hashing, plaintext, plaintext_len);
    float rate = cpu_cycles(msg_hashing, plaintext,plaintext_len);
    float Throughput = throughput(msg_hashing, plaintext, plaintext_len);
    double cpu_usage = getCurrentValue();

    //printf("Runtime: %f seconds\n", time_spent);
    printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
    printf("Runtime: %f milliseconds\n", time_spent);
    printf("Throughput: %f Bytes/second\n", Throughput);
    printf("CPU Usage: %.2f%% \n", cpu_usage);
    printf("Length: %ld", plaintext_len);
    printf("\n");


}