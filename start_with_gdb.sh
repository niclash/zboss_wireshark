#/bin/sh

source options

cd $TARGET_WIRESHARK_DIR
libtool --mode=execute cgdb ./wireshark
cd ../
