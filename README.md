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

## Set up
1. Set up libgpg-error
```
tar -xvf libgpg-error-1.49.tar.bz2
cd libgpg-error-1.49
./configure --prefix=/usr/local
make
make install

#check version
pkg-config --modversion gpg-error

#trf new gpgrt-config
cp /usr/local/bin/gpgrt-config /bin
```
2. Configure streamlined libgcrypt library
```
./configure --enable-maintainer-mode --prefix=/path/to/install --with-gpg-error-prefix=/usr/local
make 
sudo make install
```
3. Run and compile
```
gcc -Ipath/to/install/include program.c -Lpath/to/install/lib -Wl,-rpath=path/to/install/lib -lgcrypt -o program
./program
```

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
