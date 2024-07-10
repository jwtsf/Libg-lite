#!/bin/bash

echo "Starting massif analysis..."
echo -e ""


for file in *.c; do
    filename="${file%%.*}"
    gcc -I../../../install/include "$file" -L../../../install/lib -Wl,-rpath=../../../install/lib -lgcrypt -o $filename
    echo -e "----------------------------------"
    echo "Analysing $filename"
    echo -e "----------------------------------"
    echo -e ""
    valgrind --tool=massif ./$filename
    massif_out=$(ls -t massif.out.* | head -1)

    echo "Generating massif.out file: $massif_out"
    echo -e ""

    ms_print $massif_out > "$filename"_analysis.txt
    echo "Generated analysis.txt file"
    echo -e ""
    echo "Removing massif.out file"
    rm -f $massif_out
    echo -e ""
done

echo "Finished massif tests"

