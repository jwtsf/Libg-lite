/*
    gcc timer.c -lrt -lc -lm -O3 -o timer

 pi@raspberrypi ~/benchmarks/timer $ time ./timer
 Answer   500005.0, Elapsed Time 12.0059, CPU Time 11.7200, CPU Ut  98%

 real   0m12.018s
 user   0m11.710s
 sys    0m0.020s
*/
#ifndef USAGE2_H
#define USAGE2_H
#define   _POSIX_C_SOURCE 200112L
#include <time.h>
#include <stdio.h>
#define NUM_CPUS 24

double cpu_seconds(void)
{
struct timespec t;

if (!clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t))
    return (double)t.tv_sec
            + (double)t.tv_nsec / 1000000000.0;
else
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

#endif