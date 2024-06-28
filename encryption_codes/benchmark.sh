#!/bin/bash

echo "Compiling programs"
gcc -I../install/include RSA.c -L../install/lib -Wl,-rpath=../install/lib -lgcrypt -o RSA
gcc -I../install/include SHA.c -L../install/lib -Wl,-rpath=../install/lib -lgcrypt -o SHA
gcc -I../install/include AES.c -L../install/lib -Wl,-rpath=../install/lib -lgcrypt -o AES
gcc -I../install/include RSASSA.c -L../install/lib -Wl,-rpath=../install/lib -lgcrypt -o RSASSA
gcc -I../install/include ECDH.c -L../install/lib -Wl,-rpath=../install/lib -lgcrypt -o ECDH
echo "Finished Compilations"

echo -e ""
echo -e "=================================================================="

echo "Running RSA benchmark"
./RSA

echo -e ""
echo -e "=================================================================="

echo "Running SHA benchmark"
./SHA

echo -e ""
echo -e "=================================================================="


echo "Running AES benchmark"
./AES

echo -e ""
echo -e "=================================================================="


echo "Running RSASSA benchmark"
./RSASSA

echo -e ""
echo -e "=================================================================="

echo "Running ECDH benchmark"
./ECDH


echo "Finished"

./run_massif.sh