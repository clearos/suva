#!/bin/bash

function run_test()
{
	total=100
	for i in $(seq 1 $total); do
		netcat localhost 10200 &
	done
}

source $(dirname $0)/run-test.sh

# vi: ts=4
