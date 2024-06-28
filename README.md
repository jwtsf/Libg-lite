# Libg-lite

This contains a few automated benchmarking tests to measure:
1. Runtime
2. CPU cycles per byte
3. CPU Usage
4. Heap memory usage
for a streamlined version of Libgcrypt using tools such as Valgrind.

Tested algorithms:
1. AES
2. RSA
3. RSASSA
4. ECDH
5. SHA

## Usage
1. To compile and run the benchmarking tests located in encryption_codes:
```
chmod +x benchmark.sh
./benchmark.sh
```
2. To run the heap memory usage benchmarking tests using massif after:
```
chmod +x run_massif.sh
./run_massif.sh
```
