#!/bin/bash -eu
# Copyright 2024 Google LLC
# SPDX-License-Identifier: Apache-2.0

# This script is intended to be run only from the oss-fuzz docker framework
# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh
cd xen
./configure --disable-stubdom --disable-pvshim --disable-docs --disable-xen --with-system-qemu
make clang=y -C tools/include
make clang=y -C tools/fuzz/x86_instruction_emulator libfuzzer-harness
cp tools/fuzz/x86_instruction_emulator/libfuzzer-harness $OUT/x86_instruction_emulator

# Runtime coverage collection requires access to source files and symlinks don't work
cp xen/lib/x86/*.c tools/fuzz/x86_instruction_emulator
cp tools/tests/x86_emulator/*.c tools/fuzz/x86_instruction_emulator
