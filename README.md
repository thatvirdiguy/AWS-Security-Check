# AWS Security Check

Bash script to check security posturing of an AWS environment. It generates a csv for each account within the environment and logs the account, region, service, resource, rule violation, vulnerability level, and recommended remediation action for each.

## Architecture

The script is broken down into four modules, one for each of the four core services AWS provides: EC2, VPC, S3, and IAM. The main script, `security_check.sh`, calls these four modules. The findings are put in a separate folder/directory called `logs`.

## Security Checks

Currently, the script checks for the following:

- EC2 (and VPC)
  - Default VPC in use
  - Security group allows access to all ports
  - VPC flow log metric filter to log group
  - Default security group insufficiently restricts traffic
  - Volume encryption disabled
  - Instance is not in a VPC
  - Security group allows public RDP ingress
  - Security group allows public SSH ingress
  - Security group allows public HTTP ingress

- S3
  - Bucket SSE disabled
  - CloudTrail bucket is world-readable
  - Bucket is world-writeable
  - Bucket is world-readable

- IAM
  - User with console access has active access key
  - Managed policy world-accessible pass role
  - User access key not rotated in last 90 days
  - Cross-account role does not require MFA or external ID be provided
  - User credential unused for more than 90 days
  - Password policy prevents users from changing their password
  - User has policy directly attached
  - User with console access MFA disabled
