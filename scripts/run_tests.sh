#!/bin/bash

NUM_RUNS=1

OUTPUT_FILE="test_output.txt"

> $OUTPUT_FILE

for ((i=1; i<=NUM_RUNS; i++))
do
   echo "Run $i:" >> $OUTPUT_FILE
   RUSTFLAGS=-Ctarget-cpu=native cargo test --package Plonky2-lib --release --lib -- ecdsa::gadgets::ecdsa::tests::test_batch_ecdsa_cuda_circuit_narrow --exact --nocapture --ignored >> $OUTPUT_FILE 2>&1
   echo "-----------------------" >> $OUTPUT_FILE
done

echo "Tests completed. Output saved to $OUTPUT_FILE."
