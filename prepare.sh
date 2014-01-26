#!/bin/bash

source options

function err_trap () 
{
  echo "$0: line $1: exit status of last command: $2"
  exit 1
}
set -E
trap 'err_trap ${LINENO} ${$?}' ERR

if [ -d "$TARGET_WIRESHARK_DIR" ]; then
rm -rf $TARGET_WIRESHARK_DIR
fi

mkdir $TARGET_WIRESHARK_DIR

if [ ! -f "wireshark-1.10.0.tar.bz2" ]; then
wget http://wireshark.askapache.com/download/src/all-versions/wireshark-1.10.0.tar.bz2
fi

tar jxf wireshark-1.10.0.tar.bz2 -C $TARGET_WIRESHARK_DIR --strip=1

cd $TARGET_WIRESHARK_DIR
cp -fr ../$MODIFIED_FILES_DIR/* ../$TARGET_WIRESHARK_DIR
autoreconf -fi
./autogen.sh
cd ../

