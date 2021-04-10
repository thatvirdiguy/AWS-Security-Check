#!/bin/bash

mkdir -p ./logs

for profile in development staging production; do
  mkdir -p ./logs/${profile}
  printf "Account,Region,Service,Resource,Rule Violation,Vulnerability Level,Recommended Remediation Action\n" > ./logs/${profile}/`date +%d-%m-%y`.csv
done

./ec2.sh
./s3.sh
./iam.sh

