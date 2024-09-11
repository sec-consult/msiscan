#!/bin/bash

# Analyzes all msi installers in the given directory
# USAGE
# ./runall.sh <folder>

for msi in ${1}/*.msi; do
	echo "---------- $msi ----------"
	python msiscan.py "$msi"
done
