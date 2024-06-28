#!/bin/bash

echo "Starting massif analysis..."
echo -e ""

echo -e "----------------------------------"
echo "Analysing RSA"
echo -e "----------------------------------"
echo -e ""
valgrind --tool=massif ./RSA
massif_out=$(ls -t massif.out.* | head -1)

echo "Generating massif.out file: $massif_out"
echo -e ""

ms_print $massif_out > rsa_analysis.txt
echo "Generated analysis.txt file"
echo -e ""
echo "Removing massif.out file"
rm -f $massif_out
echo -e ""

echo -e "----------------------------------"
echo "Analysing RSASSA"
echo -e "----------------------------------"
echo -e ""
valgrind --tool=massif ./RSASSA
massif_out=$(ls -t massif.out.* | head -1)

echo "Generating massif.out file: $massif_out"
echo -e ""

ms_print $massif_out > rsassa_analysis.txt
echo "Generated analysis.txt file"
echo -e ""
echo "Removing massif.out file"
rm -f $massif_out
echo -e ""

echo -e "----------------------------------"
echo "Analysing AES"
echo -e "----------------------------------"
echo -e ""
valgrind --tool=massif ./AES
massif_out=$(ls -t massif.out.* | head -1)

echo "Generating massif.out file: $massif_out"
echo -e ""

ms_print $massif_out > aes_analysis.txt
echo "Generated analysis.txt file"
echo -e ""
echo "Removing massif.out file"
rm -f $massif_out
echo -e ""

echo -e "----------------------------------"
echo "Analysing SHA"
echo -e "----------------------------------"
echo -e ""
valgrind --tool=massif ./SHA
massif_out=$(ls -t massif.out.* | head -1)

echo "Generating massif.out file: $massif_out"
echo -e ""

ms_print $massif_out > sha_analysis.txt
echo "Generated analysis.txt file"
echo -e ""
echo "Removing massif.out file"
rm -f $massif_out
echo -e ""

echo -e "----------------------------------"
echo "Analysing ECDH"
echo -e "----------------------------------"
echo -e ""
valgrind --tool=massif ./ECDH
massif_out=$(ls -t massif.out.* | head -1)

echo "Generating massif.out file: $massif_out"
echo -e ""

ms_print $massif_out > ecdh_analysis.txt
echo "Generated analysis.txt file"
echo -e ""
echo "Removing massif.out file"
rm -f $massif_out
echo -e ""

echo "Finished"
