#ifndef RUNTIME_H
#define RUNTIME_H

#define _POSIX_C_SOURCE 200809L
#include "../../install/include/gcrypt.h"
#include "cycle-timings.h"
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/random.h>
#include <string.h>
#include <sys/sysinfo.h>
#include "cpu-usage.h"

//========================================//
//-- MISC --------------------------------//
//========================================//

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

//read file into buffer
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
        unsigned char* buffer = (unsigned char*)malloc(*padded_size);

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


struct timespec start, end;
//========================================//
//-- Runtime -----------------------------//
//========================================//

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t, int, unsigned char*), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext)
{
    
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    int x = (*f)(plaintext, key, IV, plaintext_len, key_len, IV_len, cipher, ciphertext);

    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    const uint64_t ns = (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);
    float time_spent = ns;

    return time_spent;
}

//========================================//
//-- CPU cycles --------------------------//
//========================================//

//This measures CPU cycles for encryption process
float cpu_cycles(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t, int, unsigned char*), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext)
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

        int x = (*f)(plaintext, key, IV, plaintext_len, key_len, IV_len, cipher, ciphertext);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//========================================//
//-- Throughput --------------------------//
//========================================//

//This measures throughput
float throughput(int (*f)(unsigned char* , unsigned char* , unsigned char* ,size_t, size_t, size_t, int, unsigned char*), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len, int cipher, unsigned char *ciphertext)
{
    int byte_length_of_processed_data = plaintext_len;
    float time = cpu_time(f, plaintext, key, IV, plaintext_len, key_len, IV_len, cipher, ciphertext);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}

#endif