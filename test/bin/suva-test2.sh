#!/bin/bash

function run_test()
{
	fail=0
	success=0
	total=100
	for i in $(seq 1 $total); do
		reply=$(netcat localhost 10200)
		printf "Test #%2d / %2d: " $i $total
		if [ "$reply" != "Hello!" ]; then
			echo "FAIL"
			fail=$[ $fail + 1]
		else
			echo "OK"
			success=$[ $success + 1]
		fi
	done
	printf "Results, %d failures, %d successful.\n" $fail $success
}

source $(dirname $0)/run-test.sh

# vi: ts=4
