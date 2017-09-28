#! /bin/bash

# Should automate testing the breakdown (i.e. run per file)
files=( "test_10KB_NULL_4KB.capsule" "test_1M_NULL_1KB.capsule" "test_1M_NULL_4KB.capsule" )
iter=10
ops=( 0 1 2 3 4 )
# 0 - open, 1 - close, 2 - lseek, 3 - read, 4 - write

# Iterate over files and ops
for f in "${files[@]}"
do
    echo "\n\nTesting $f"
	for op in "${ops[@]}"
	do
		capsule_breakdown BENCHMARK "/etc/test_capsules/$f" $iter $op
	done
done
