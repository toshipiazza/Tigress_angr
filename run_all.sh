#!/bin/bash

for i in tigress-0-challenge-0 \
         tigress-0-challenge-1 \
         tigress-0-challenge-2 \
         tigress-0-challenge-3 \
         tigress-0-challenge-4; do
  ./tigress.py ./tigress-challenges/$i -l output/$i.ll
done

# for i in tigress-1-challenge-0 \
#          tigress-1-challenge-1 \
#          tigress-1-challenge-2 \
#          tigress-1-challenge-3 \
#          tigress-1-challenge-4; do
#   ./tigress.py ./tigress-challenges/$i -l output/$i.ll
# done

# for i in tigress-2-challenge-0 \
#          tigress-2-challenge-1 \
#          tigress-2-challenge-2 \
#          tigress-2-challenge-3 \
#          tigress-2-challenge-4; do
#   ./tigress.py ./tigress-challenges/$i -l output/$i.ll
# done

# for i in tigress-3-challenge-0 \
#          tigress-3-challenge-1 \
#          tigress-3-challenge-2 \
#          tigress-3-challenge-3 \
#          tigress-3-challenge-4; do
#   ./tigress.py ./tigress-challenges/$i -l output/$i.ll
# done

# for i in tigress-4-challenge-0 \
#          tigress-4-challenge-1 \
#          tigress-4-challenge-2 \
#          tigress-4-challenge-3 \
#          tigress-4-challenge-4; do
#   ./tigress.py ./tigress-challenges/$i -l output/$i.ll
# done
