#!/bin/sh

set -xe

fasm hello.S
chmod +x ./hello

gcc -s hello1.c  -Wl,-gc-sections -Wl,--print-gc-sections -o hello1_gcc
chmod +x ./hello1_gcc
./elf.py -f ./hello1_gcc
