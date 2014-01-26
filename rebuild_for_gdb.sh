#/bin/sh

source options

trap 'err' ERR
rebuild_for_gdb
