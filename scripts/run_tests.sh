#!/bin/bash

# 设置要运行的次数
NUM_RUNS=1

# 输出文件名
OUTPUT_FILE="test_output.txt"

# 清空之前的输出文件内容
> $OUTPUT_FILE

# 循环运行命令并将输出追加到文件
for ((i=1; i<=NUM_RUNS; i++))
do
   echo "Run $i:" >> $OUTPUT_FILE
   RUSTFLAGS=-Ctarget-cpu=native cargo test --package Plonky2-lib --release --lib -- ecdsa::gadgets::ecdsa::tests::test_batch_ecdsa_circuit_narrow --exact --nocapture --ignored >> $OUTPUT_FILE 2>&1
   echo "-----------------------" >> $OUTPUT_FILE
done

echo "Tests completed. Output saved to $OUTPUT_FILE."
