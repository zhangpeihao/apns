#!/bin/bash

function usage
{
	echo "run.sh <test|release>"
	exit 1
}

MODE=$1

case ${MODE} in
	'test')
		./server
		;;
	'release')
		;;
	*)
		usage
		;;
esac