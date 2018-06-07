#!/usr/bin/env bash

for i in output/*.ll; do
  clang-3.9 $i template.c -o ${i%.ll} -Wno-override-module
done
