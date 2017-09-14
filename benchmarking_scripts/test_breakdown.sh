#! /bin/bash

# Should automate testing the breakdown (i.e. run per file)
files=( "" )
iter=100
ops=( 0 1 2 3 4 )
# 0 - open, 1 - close, 2 - lseek, 3 - read, 4 - write

# Iterate over files and ops
for f in "${files[@]}"
do
	for op in "${ops[@]}"
	do
		# Clear the benchmark
		capsule_benchmark CLEAR
		capsule_benchmark BENCHMARK $f $iter $op
		capsule_benchmark DISPLAY
	done
done
