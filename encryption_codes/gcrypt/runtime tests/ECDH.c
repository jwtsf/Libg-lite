#define _POSIX_C_SOURCE 200809L
#include "cpu-usage.h"
#include "compiled.h"
#include "cycle-timings.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>
struct timespec start, end;
//#define ECC_CURVE_NAME "prime256v1" // Use "prime256v1" for NIST P-256 curve
float cpu_time(int (*f)(unsigned char* ), unsigned char *curvename)
{
    
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    int x = (*f)(curvename);

    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    const uint64_t ns = (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);
    float time_spent = ns;

    return time_spent;
}
//This measures CPU cycles for encryption process
float cpu_cycles(int (*f)(unsigned char* ), unsigned char *curvename)
{

    //Measure the overhead of timing

    uint64_t timing_overhead;
    timing_overhead = measure_overhead();
    printf("Timing overhead: %lu clock cycles\n", timing_overhead);


    //Compute the length of processed data 

    int byte_length_of_processed_data = 32;
    float rate;

    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        temp = start_timer();

        int x = (*f)(curvename);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)(unsigned char* ), unsigned char *curvename)
{
    int byte_length_of_processed_data = 32;
    float time = cpu_time(f, curvename);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}

int main() {
    unsigned char *curve_name = "nistp256";  // Example curve name, replace with your desired curve
    //int result = ecdh_secret_generation(curve_name, NULL, NULL, 0, 0, 0, 0, NULL);
    init();
    float time_spent = (cpu_time(ecdh_secret_generation, curve_name))/1000000;
    float cycles = cpu_cycles(ecdh_secret_generation, curve_name);
    float thr = throughput(ecdh_secret_generation, curve_name);
    double cpu_usage = getCurrentValue();
    printf("-------------------------------------------------------\n");
    printf("ECDH Secret Generation\n");
    printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", cycles);
    printf("Runtime: %f milliseconds\n", time_spent);
    printf("Throughput: %f Bytes/second\n", thr);
    printf("CPU Usage: %.2f%% \n", cpu_usage);
    printf("Processed Bytes: %d bytes\n", 32);
    printf("\n");
    return 0;
}
