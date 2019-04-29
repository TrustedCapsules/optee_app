#!/bin/bash
set -e

if [[ $# -eq 0 ]] ; then
    echo 'Usage: pass path to the capsule folder'
    exit 0;
fi

for capsule in `ls $1`; do
    name=$(basename "$capsule")
    echo "Making capsule '$name'"
    cmd/cgen/cgen encode -n ${name} -p $1/${name}/ -o $1/${name}/
    cp $1/${name}/* capsules/new_capsules
done
