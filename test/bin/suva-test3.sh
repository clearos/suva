#!/bin/bash

function run_test()
{
	fail=0
	success=0
	total=1
	for i in $(seq 1 $total); do
		printf "Test #%2d / %2d\n" $i $total
		#dd if=/dev/urandom bs=1M count=100 | netcat localhost 10400
		dd if=/dev/zero bs=10M count=100 | netcat localhost 10400
	done
	#printf "Results, %d failures, %d successful.\n" $fail $success
}

source $(dirname $0)/run-test.sh

# vi: ts=4
