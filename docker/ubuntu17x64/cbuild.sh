#!/bin/bash

OLD_IFS="$IFS"
IFS=";"
code_path_list=($CODE)
IFS="$OLD_IFS"

output=$OUTPATH/ubuntu17x64/$(date +%Y%m%d_%s)/
mkdir -p $output
for code_path in ${code_path_list[@]}
do
    cd $code_path
    make clean;make
    cp *.so $output
done
