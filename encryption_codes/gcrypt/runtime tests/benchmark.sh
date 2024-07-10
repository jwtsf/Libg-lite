#!/bin/bash
for file in *.c; do
    filename="${file%%.*}"
    gcc -I../../../install/include "$file" -L../../../install/lib -Wl,-rpath=../../../install/lib -lgcrypt -o $filename
    echo -e ""
    echo -e "=================================================================="

    echo "Running $filename benchmark"
    ./$filename

    echo -e ""
done

echo -e ""
echo "Finished"
