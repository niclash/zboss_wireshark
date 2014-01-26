#/bin/sh

source options

trap 'err' ERR
rebuild
