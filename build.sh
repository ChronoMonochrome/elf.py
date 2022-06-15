#!/bin/sh

set -xe

fasm hello.S
chmod +x ./hello
./elf.py -f ./hello
