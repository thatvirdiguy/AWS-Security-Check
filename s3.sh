#!/bin/bash

region_list='us-west-1 sa-east-1 eu-west-1 ap-southeast-1'

for profile in internal staging production; do
  aws --profile ${profile} s3api list-buckets | jq -r '.Buckets[] | .Name' > /tmp/list-buckets.out

  while read bucket_name; do
    region=$(aws --profile ${profile} s3api get-bucket-location --bucket ${bucket_name} | jq -r '.LocationConstraint')

    # Severe | S3 : Simple Storage Service : Bucket SSE disabled
    bucket_encryption=$(aws --profile ${profile} s3api get-bucket-encryption --bucket ${bucket_name} 2>/dev/null)
    if [[ ${bucket_encryption} == "" ]]; then
      printf "${profile},${region},S3,${bucket_name},Bucket SSE disabled,Severe,Enable server-side encryption to use S3-managed keys (SSE-S3)\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
    fi

    bucket_policy=$(aws --profile ${profile} s3api get-bucket-policy --bucket ${bucket_name} --output text 2>/dev/null)
    if [[ ${bucket_policy} != "" ]]; then
      bucket_policy_principal=$(echo ${bucket_policy} | jq -r '.Statement[].Principal')
      bucket_policy_action=$(echo ${bucket_policy} | jq -r '.Statement[].Action')
      
      # Critical | S3 : Simple Storage Service : Bucket is world-readable
      if [[ ${bucket_policy_principal} == "*" ]] && [[ `echo ${bucket_policy_action} | grep -i -q "Get"` ]]; then
        printf "${profile},${region},S3,${bucket_name},Bucket is world-readable,Critical,Update bucket policy to limit access\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi

      # Critical | S3 : Simple Storage Service : Bucket is world-writeable
      if [[ ${bucket_policy_principal} == "*" ]] && [[ `echo ${bucket_policy_action} | grep -i -q "Put"` ]]; then
        printf "${profile},${region},S3,${bucket_name},Bucket is world-writeable,Critical,Update bucket policy to limit access\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi
    fi

  done < /tmp/list-buckets.out

  # Critical | S3 : Simple Storage Service : CloudTrail bucket is world-readable
  for region in ${region_list}; do
    aws --profile ${profile} --region ${region} cloudtrail describe-trails | jq -r '.trailList[].S3BucketName' > /tmp/cloudtrail-buckets.out
    while read trail_bucket; do
      grantee_group_url=$(aws --profile ${profile} s3api get-bucket-acl --bucket ${trail_bucket} | jq -r '.Grants[].URI?')
        if [[ `echo ${grantee_group_url} | grep "AllUsers"` ]]; then
          printf "${profile},${region},S3,${trail_bucket},CloudTrail bucket is world-readable,Critical,Update bucket ACL to limit access\n" ./logs/${profile}/`date +%d-%m-%y`.csv
        fi
    done < /tmp/cloudtrail-buckets.out
  done

done
  
