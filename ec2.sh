#!/bin/bash

region_list='us-west-1 sa-east-1 eu-west-1 ap-southeast-1'

for profile in internal staging production; do
  for region in ${region_list}; do
    aws --profile ${profile} ec2 describe-instances --region ${region} | jq '.' > /tmp/instances.out
    aws --profile ${profile} ec2 describe-vpcs --region ${region} | jq '.' > /tmp/vpcs.out
    aws --profile ${profile} ec2 describe-security-groups --region ${region} | jq '.' > /tmp/security_groups.out
    aws --profile ${profile} ec2 describe-volumes --region ${region} | jq '.' > /tmp/volumes.out
    
    cat /tmp/instances.out | jq -r '.Reservations[].Instances[] | [ .InstanceId, .VpcId ] | join(",")' > /tmp/instance-vpc

    cat /tmp/vpcs.out | jq -r '.Vpcs[] | [ .VpcId, .IsDefault ] | @csv' | sed 's|"||g' > /tmp/vpc-default

    cat /tmp/instances.out | jq -r '.Reservations[].Instances[] | [ .InstanceId, .SecurityGroups[]?.GroupId ] | join (",")' > /tmp/instance-sec_grp

    while read line; do
      instance_id=$(echo ${line} | awk -F ',' '{print $1}')
      vpc_id=$(echo ${line} | awk -F ',' '{print $2}')

      # Critical | EC2 : Elastic Compute Cloud : Instance is not in a VPC
      if [[ ${vpc_id} == "null" ]]; then
        printf "${profile},${region},EC2,${instance_id},Instance is not in a VPC,Critical,Clone the instance by creating an AMI and launch AMI-based instance in VPC\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi
      
      # Severe | EC2 : Elastic Compute Cloud : Default VPC in use
      if [[ `cat /tmp/vpc-default | grep -q ${vpc_id} | grep -q -i "true"` ]]; then
        printf "${profile},${region},EC2,${vpc_id},Default VPC in use,Severe,Create a new VPC with the desired CIDR and migrate the instance there\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi
    done < /tmp/instance-vpc

    # Severe | EC2 : Elastic Compute Cloud : Security group allows access to all ports
    cat /tmp/security_groups.out | jq -r '.SecurityGroups[] | if .IpPermissions[].IpProtocol == "-1" then .GroupId else empty end' | uniq > /tmp/open_all_sec_grps

    while read open_sec_grp; do
      if grep -q ${open_sec_grp} /tmp/instance-sec_grp; then
        echo ${open_sec_grp} >> /tmp/open_all_sec_grps_v2
      fi
    done < /tmp/open_all_sec_grps

    while read sec_grp; do
      cat /tmp/security_groups.out | jq -r --arg sec_grp "$sec_grp" '.SecurityGroups[] | select(.GroupId==$sec_grp)' > /tmp/open_all_sec_grp_details
      cat /tmp/open_all_sec_grp_details | jq -r '.IpPermissions[] | if .UserIdGroupPairs == [] and .IpProtocol == "-1" then . else empty end' > /tmp/open_all_sec_grp_rule
      cat /tmp/open_all_sec_grp_rule | jq -r '.IpRanges[]?.CidrIp' > /tmp/open_all_sec_grp_ips
      if [[ `cat /tmp/open_all_sec_grp_ips | wc -l` != "0" ]]; then
        echo ${sec_grp} >> /tmp/open_all_sec_grps_updated
      fi
      if grep -q ${sec_grp} /tmp/open_all_sec_grps_updated; then
        while read source_ip; do
          if [[ ${source_ip} == "0.0.0.0/0" ]]; then
            printf "${profile},${region},EC2,${sec_grp},Security group allows access to all ports,Severe,Update security group rule allowing open access\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
          fi
        done < /tmp/open_all_sec_grp_ips
      fi
    done < /tmp/open_all_sec_grps_v2

    rm -rf /tmp/open_all_sec_grps_v2 /tmp/open_all_sec_grps_updated

    # Critical | EC2 : Elastic Compute Cloud : Security group allows public SSH ingress
    cat /tmp/security_groups.out | jq -r '.SecurityGroups[] | if .IpPermissions[].FromPort? == 22 then .GroupId else empty end' | uniq > /tmp/open_ssh_sec_grps

    while read open_ssh_sec_grp; do
      if grep -q ${open_ssh_sec_grp} /tmp/instance-sec_grp; then
        echo ${open_ssh_sec_grp} >> /tmp/open_ssh_sec_grps_v2
      fi
    done < /tmp/open_ssh_sec_grps

    while read sec_grp; do
      cat /tmp/security_groups.out | jq -r --arg sec_grp "$sec_grp" '.SecurityGroups[] | select(.GroupId==$sec_grp)' > /tmp/open_ssh_sec_grp_details
      cat /tmp/open_ssh_sec_grp_details | jq -r '.IpPermissions[] | if .UserIdGroupPairs == [] and .FromPort? == 22 then . else empty end' > /tmp/open_ssh_sec_grp_rule
      cat /tmp/open_ssh_sec_grp_rule | jq -r '.IpRanges[]?.CidrIp' > /tmp/open_ssh_sec_grp_ips
      if [[ `cat /tmp/open_ssh_sec_grp_ips | wc -l` != "0" ]]; then
        echo ${sec_grp} >> /tmp/open_ssh_sec_grps_updated
      fi
      if grep -q ${sec_grp} /tmp/open_ssh_sec_grps_updated; then
        while read source_ip; do
          if [[ ${source_ip} == "0.0.0.0/0" ]]; then
            printf "${profile},${region},EC2,${sec_grp},Security group allows public SSH ingress,Critical,Update security group rule allowing public SSH access\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
          fi
        done < /tmp/open_ssh_sec_grp_ips
      fi
    done < /tmp/open_ssh_sec_grps_v2
    
    rm -rf /tmp/open_ssh_sec_grps_v2 /tmp/open_ssh_sec_grps_updated

    # Critical | EC2 : Elastic Compute Cloud : Security group allows public RDP ingress
    cat /tmp/security_groups.out | jq -r '.SecurityGroups[] | if .IpPermissions[].FromPort? == 3389 then .GroupId else empty end' | uniq > /tmp/open_rdp_sec_grps

    while read open_rdp_sec_grp; do
      if grep -q ${open_rdp_sec_grp} /tmp/instance-sec_grp; then
        echo ${open_rdp_sec_grp} >> /tmp/open_rdp_sec_grps_v2
      fi
    done < /tmp/open_rdp_sec_grps

    while read sec_grp; do
      cat /tmp/security_groups.out | jq -r --arg sec_grp "$sec_grp" '.SecurityGroups[] | select(.GroupId==$sec_grp)' > /tmp/open_rdp_sec_grp_details
      cat /tmp/open_rdp_sec_grp_details | jq -r '.IpPermissions[] | if .UserIdGroupPairs == [] and .FromPort? == 3389 then . else empty end' > /tmp/open_rdp_sec_grp_rule
      cat /tmp/open_rdp_sec_grp_rule | jq -r '.IpRanges[]?.CidrIp' > /tmp/open_rdp_sec_grp_ips
      if [[ `cat /tmp/open_rdp_sec_grp_ips | wc -l` != "0" ]]; then
        echo ${sec_grp} >> /tmp/open_rdp_sec_grps_updated
      fi
      if grep -q ${sec_grp} /tmp/open_rdp_sec_grps_updated; then
        while read source_ip; do
          if [[ ${source_ip} == "0.0.0.0/0" ]]; then
            printf "${profile},${region},EC2,${sec_grp},Security group allows public RDP ingress,Critical,Update security group rule allowing public RDP access\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
          fi
        done < /tmp/open_rdp_sec_grp_ips
      fi
    done < /tmp/open_rdp_sec_grps_v2

    rm -rf /tmp/open_rdp_sec_grps_v2 /tmp/open_rdp_sec_grps_updated

    # Critical | EC2 : Elastic Compute Cloud : Security group allows public HTTP ingress
    cat /tmp/security_groups.out | jq -r '.SecurityGroups[] | if .IpPermissions[].FromPort? == 80 then .GroupId else empty end' | uniq > /tmp/open_http_sec_grps

    while read sec_grp; do
      if grep -q ${open_http_sec_grp} /tmp/instance-sec_grp; then
        echo ${open_http_sec_grp} >> /tmp/open_http_sec_grps_v2
      fi
    done < /tmp/open_http_sec_grps

    while read sec_grp; do
      cat /tmp/security_groups.out | jq -r --arg sec_grp "$sec_grp" '.SecurityGroups[] | select(.GroupId==$sec_grp)' > /tmp/open_http_sec_grp_details
      cat /tmp/open_http_sec_grp_details | jq -r '.IpPermissions[] | if .UserIdGroupPairs == [] and .FromPort? == 80 then . else empty end' > /tmp/open_http_sec_grp_rule
      cat /tmp/open_http_sec_grp_rule | jq -r '.IpRanges[]?.CidrIp' > /tmp/open_http_sec_grp_ips
      if [[ `cat /tmp/open_http_sec_grp_ips | wc -l` != "0" ]]; then
        echo ${sec_grp} >> /tmp/open_http_sec_grps_updated
      fi
      if grep -q ${sec_grp} /tmp/open_http_sec_grps_updated; then
        while read source_ip; do
          if [[ ${source_ip} == "0.0.0.0/0" ]]; then
            printf "${profile},${region},EC2,${sec_grp},Security group allows public HTTP ingress,Critical,Update security group rule allowing public HTTP access\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
          fi
        done < /tmp/open_http_sec_grp_ips
      fi
    done < /tmp/open_http_sec_grps_v2

    rm -rf /tmp/open_http_sec_grps_v2 /tmp/open_http_sec_grps_updated

    # Severe | EC2 : Elastic Compute Cloud : Default security group insufficiently restricts traffic
    cat /tmp/security_groups.out | jq -r '.SecurityGroups[] | if .GroupName == "default" and select(.IpPermissions[]|length) != 0 then .GroupId else empty end' | uniq > /tmp/sec_grp-default

    while read default_sec_grp; do
      if grep -q ${default_sec_grp} /tmp/instance-sec_grp; then
        printf "${profile},${region},EC2,${vpc_id},Default security group insufficiently restricts traffic,Severe,Create least-privilege security groups for the resources currently in the default security group and move those resources to the newly-created least-privilege security groups\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi
    done < /tmp/sec_grp-defaut 

    # Severe | EC2 : Elastic Compute Cloud : Volume encryption disabled
    cat /tmp/volumes.out | jq -r '.Volumes[] | [ .Attachments[].InstanceId, .Attachments[].VolumeId, .Encrypted ] | @csv' | sed 's/\"//g' > /tmp/volume-encryption

    while read line; do
      vol_id=$(echo ${line} | awk -F ',' '{print $2}')
      encryption_status=$(echo ${line} | awk -F ',' '{print $3}')
        if [[ ${encryption_status} == "false" ]]; then
          printf "${profile},${region},EC2,${vol_id},Volume encryption disabled,Severe,Create encrypted snapshot of the existing volume and then create a new volume from that snapshot\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
        fi
    done < /tmp/volume-encryption

    # Severe | EC2 : Elastic Compute Cloud : VPC flow log metric filter disabled
    aws --profile ${profile} --region ${region} ec2 describe-flow-logs | jq -r '.FlowLogs[] | [ .LogGroupName, .ResourceId ] | join(",")' > /tmp/vpc-flow_logs
    
    while read line; do
      log_group_name=$(echo ${line} | awk -F ',' '{print $1}')
      vpc_id=$(echo ${line} | awk -F ',' '{print $2}')
      log_metric_filter=$(aws --profile ${profile} --region ${region} ec2 describe-flow-logs | jq -r '.FlowLogs[] | [ .LogGroupName, .ResourceId ] | join(",")' 2>/dev/null)
      if [[ ${log_metric_filter} == "" ]]; then
        printf "${profile},${region},EC2,${vpc_id},VPC flow log metric filter disabled,Severe,Create and configure a metric filter for the VPC with with a pattern that matches {$.errorCode = \"AccessDenied\"}\n" >> ./logs/${profile}/`date +%d-%m-%y`.csv
      fi
     done < /tmp/vpc-flow_logs 

  done
done
