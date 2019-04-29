#!/bin/bash
set -e

if [[ $# -eq 0 ]] ; then
    echo 'Usage: pass path to the capsule folder'
    exit 0;
fi

for capsule in `ls $1`; do
    name=$(basename "$capsule")
    echo "Registering $name"
    cmd/cprov/cprov -n ${name} -p $1/${name}
done  
