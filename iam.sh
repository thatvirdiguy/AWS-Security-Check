#!/bin/bash

region_list='Global'

for profile in internal staging production; do
  for region in ${region_list}; do

    aws --profile ${profile} --region ${region} iam list-users > /tmp/iam_users.out
    aws --profile ${profile} --region ${region} iam list-roles > /tmp/iam_roles.out
    aws --profile ${profile} --region ${region} iam list-policies --only-attached --scope Local > /tmp/iam_policies.out

    cat /tmp/iam_users.out | jq -r '.Users[] | .UserName' > /tmp/iam_username

    # Severe | IAM : Identity and Access Management : User has policy directly attached
    while read username; do
      user_policy_list=$(aws --profile ${profile} --region ${region} iam list-attached-user-policies --user-name ${username} | jq -r '.AttachedPolicies[]?.PolicyName?')
      if [[ ${user_policy_list} != "" ]]; then
        printf "${profile},${region},IAM,${username},User has policy directly attached,Severe,Use groups or roles to grant user access to the desired policies\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi
    done < /tmp/iam_username

    # Severe | IAM : Identity and Access Management : User access key not rotated in last 90 days
    while read username; do
      dateThreshold=$(date -d "90 days ago" +%Y-%m-%dT%H:%M:%SZ)
      dateKeys=$(aws --profile ${profile} iam list-access-keys --user ${username} | jq -r '.AccessKeyMetadata[]? | if .Status == "Active" then .CreateDate else empty end' 2>/dev/null)
      for dateK in ${dateKeys}; do
        if [[ ${dateK} != "" ]]; then
          start=$(date -d `echo ${dateK} | awk -F 'T' '{print $1}'` +%s)
          end=$(date -d `echo ${dateThreshold} | awk -F 'T' '{print $1}'` +%s)
          diff=$((($end-$start)/(60*60*24)))
          if [[ ${diff} -gt "90" ]] ; then
            printf "${profile},${region},IAM,${username},User access key not rotated in last 90 days,Severe,Rotate the active access key for the user\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
          fi
        fi
      done
    done < /tmp/iam_username

    # Severe | IAM : Identity and Access Management : Cross-account role does not require MFA or external ID be provided
    cat /tmp/iam_roles.out | jq -r '.Roles[].RoleName' > /tmp/rolename
    while read rolename; do
      role_principal=$(aws --profile ${profile} iam get-role --role-name ${rolename} | jq -c '.Role.AssumeRolePolicyDocument.Statement[].Principal')
      role_condtion=$(aws --profile ${profile} iam get-role --role-name ${rolename} | jq -c '.Role.AssumeRolePolicyDocument.Statement[].Condition[]?')
      if [[ `echo ${role_principal} | grep "AWS"` ]]; then
        if [[ ${role_condition} == "" ]]; then
          printf "${profile},${region},IAM,${rolename},Cross-account role does not require MFA or external ID be provided,Severe,Update the role policy document by adding conditions that enable MFA or external ID support\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
        else
          if [[ `echo ${role_condition} | sed s'/"//'g | grep -v "{aws:MultiFactorAuthPresent:false}"` ]] && [[ `echo ${role_condition} | sed s'/"//'g | grep -v "{sts:ExternalId:}"` ]]; then
            printf "${profile},${region},IAM,${rolename},Cross-account role does not require MFA or external ID be provided,Severe,Update the role policy document by adding conditions that enable MFA or external ID support\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
          fi
        fi
      fi
    done < /tmp/rolename

    # Severe | IAM : Identity and Access Management : Managed policy world-accessible pass role
    cat /tmp/iam_policies.out | jq -r '.Policies[] | [ .PolicyName, .Arn, .DefaultVersionId ] | @csv' | sed 's/"//g' > /tmp/policydetails
    while read line; do
      policy_name=$(echo ${line} | awk -F ',' '{print $1}')
      policy_arn=$(echo ${line} | awk -F ',' '{print $2}')
      policy_versionid=$(echo ${line} | awk -F ',' '{print $3}')
      aws --profile ${profile} --region ${region} iam get-policy-version --policy-arn ${policy_arn} --version-id ${policy_versionid} > /tmp/policydoc
      cat /tmp/policydoc | jq -r '.PolicyVersion.Document.Statement[] | if .Effect == "Allow" and .Resource == "*" then .Action[]? else empty end' > /tmp/policypermissions
      if grep -q "iam:PassRole" /tmp/policypermissions; then
        printf "${profile},${region},IAM,${policy_name},Managed policy world-accessible pass role,Severe,Use the console to add policy conditions\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi 
    done < /tmp/policydetails

    # Severe | IAM : Identity and Access Management : Password policy prevents users from changing their password
    password_change=$(aws --profile ${profile} --region ${region} iam get-account-password-policy | jq '.PasswordPolicy.AllowUsersToChangePassword')
    if [[ ${password_change} == "false" ]]; then
      printf "${profile},${region},IAM,Account Password Policy,Password policy prevents users from changing their password,Severe,Set \"AllowUsersToChangePassword\" in the account password policy to false\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
    fi
      
    # Severe | IAM : Identity and Access Management : User credential unused for more than 90 days
    aws --profile ${profile} --region ${region} iam generate-credential-report > /dev/null
    aws --profile ${profile} --region ${region} iam get-credential-report --output text --query Content | base64 -d > /tmp/iam_credential_report
    sed '1d' /tmp/iam_credential_report > /tmp/iam_credential_report_updated
    while read line; do
      username=$(echo ${line} | awk -F ',' '{print $1}')
      password_enabled=$(echo ${line} | awk -F ',' '{print $4}')
      password_last_changed=$(echo ${line} | awk -F ',' '{print $6}')
      if [[ ${password_enabled} == "true" ]]; then
        dateThreshold=$(date -d "90 days ago" +%Y-%m-%dT%H:%M:%SZ)
        start=$(date -d `echo ${password_last_changed} | awk -F 'T' '{print $1}'` +%s)
        end=$(date -d `echo ${dateThreshold} | awk -F 'T' '{print $1}'` +%s)
        diff=$((($end-$start)/(60*60*24)))
        if [[ ${diff} -gt "90" ]] ; then
          printf "${profile},${region},IAM,${username},User credential unused for more than 90 days,Severe,Consider deleting login profile for user\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
        fi
      fi
    done < /tmp/iam_credential_report_updated

    # Severe | IAM : Identity and Access Management : User with console access has active access key
    while read username; do
      aws --profile ${profile} --region ${region} iam get-login-profile --user-name ${username} > /dev/null 2>&1
      if [[ `echo $?` == "0" ]]; then
        access_key_status=$(aws --profile ${profile} --region ${region} iam list-access-keys --user ${username} | jq -r '.AccessKeyMetadata[].Status')
        if [[ ${access_key_status} == "Active" ]]; then
          printf "${profile},${region},IAM,${username},User with console access has active access key,Severe,Disable either the login profile or the active access key for user\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
        fi
      fi
    done < /tmp/iam_username

    # Critical | IAM : Identity and Access Management : User with console access MFA disabled
     while read username; do
       aws --profile ${profile} --region ${region} iam get-login-profile --user-name ${username} > /dev/null 2>&1
       if [[ `echo $?` == "0" ]]; then
         mfa_devices=$(aws --profile ${profile} --region ${region} iam list-mfa-devices --user-name ${username} | jq -r '.MFADevices[]')
         if [[ ${mfa_devices} == "" ]]; then
           printf "${profile},${region},IAM,${username},User with console access MFA disabled,Critical,Enable at least one MFA device or disable console access for user\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
         fi
       fi
     done < /tmp/iam_username

  done
done
