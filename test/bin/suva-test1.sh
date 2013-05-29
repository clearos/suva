#!/bin/bash -x

function run_test()
{
	fail=0
	success=0
	total=5
	for i in $(seq 1 $total); do
		reply=$(echo -e "client-test\nHello\n-1\nk0r3dump.net\nlocalhost\n1234\n" | netcat localhost 10301 | grep -v iSFD)
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
