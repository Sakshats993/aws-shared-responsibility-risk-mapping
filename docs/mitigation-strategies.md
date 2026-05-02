# 🛡️ AWS Security Mitigation Strategies

## Overview

This document provides actionable mitigation strategies for each risk
category, including AWS CLI commands, policy examples, and Terraform snippets.

---

## 1. IAM Mitigation Strategies

### 1.1 Enforce MFA for All Users

**IAM Policy to Deny Actions Without MFA:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyWithoutMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### 1.2 IAM Password Policy

```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24
```

### 1.3 Access Key Rotation Script

```bash
#!/bin/bash
# List all users and their access key ages
aws iam list-users --query 'Users[].UserName' --output text | \
  tr '\t' '\n' | while read username; do
    aws iam list-access-keys --user-name "$username" \
      --query 'AccessKeyMetadata[].{User:UserName,Key:AccessKeyId,Created:CreateDate,Status:Status}' \
      --output table
done
```

### 1.4 Use IAM Roles Instead of Access Keys

```bash
# Create role for EC2 instances
aws iam create-role \
  --role-name EC2-App-Role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach SSM policy for Session Manager access
aws iam attach-role-policy \
  --role-name EC2-App-Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

# Create instance profile
aws iam create-instance-profile --instance-profile-name EC2-App-Profile
aws iam add-role-to-instance-profile \
  --instance-profile-name EC2-App-Profile \
  --role-name EC2-App-Role
```

---

## 2. Networking Mitigation Strategies

### 2.1 Secure Security Group Configuration

```bash
# Remove SSH open to 0.0.0.0/0
aws ec2 revoke-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Add SSH only from specific IP
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 22 \
  --cidr 203.0.113.10/32
```

### 2.2 Enable VPC Flow Logs

```bash
# Create CloudWatch log group
aws logs create-log-group --log-group-name /vpc/flow-logs

# Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /vpc/flow-logs \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/VPCFlowLogsRole
```

### 2.3 VPC Architecture Best Practices

```
Recommended VPC Structure:
┌─────────────────────────────────────────────────────┐
│                        VPC                           │
│  ┌─────────────────┐    ┌─────────────────────────┐ │
│  │  Public Subnet  │    │     Private Subnet       │ │
│  │                 │    │                          │ │
│  │  ALB/NLB        │───▶│  EC2/ECS/Lambda          │ │
│  │  NAT Gateway    │    │  RDS/ElastiCache         │ │
│  │  Bastion (opt.) │    │  Internal Services       │ │
│  └─────────────────┘    └─────────────────────────┘ │
│           │                                          │
│  Internet Gateway                                    │
└───────────┼──────────────────────────────────────────┘
            │
       Internet
```

### 2.4 Network ACL Configuration

```bash
# Create restrictive NACL for private subnet
aws ec2 create-network-acl --vpc-id vpc-12345678

# Allow inbound HTTP/HTTPS from ALB subnet only
aws ec2 create-network-acl-entry \
  --network-acl-id acl-12345678 \
  --rule-number 100 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 10.0.1.0/24 \
  --port-range From=80,To=443

# Deny all other inbound
aws ec2 create-network-acl-entry \
  --network-acl-id acl-12345678 \
  --rule-number 32766 \
  --protocol -1 \
  --rule-action deny \
  --ingress \
  --cidr-block 0.0.0.0/0
```

---

## 3. Storage (S3) Mitigation Strategies

### 3.1 Block All Public Access (Account Level)

```bash
# Block public access for entire account (most important step)
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
    BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 3.2 Enable Default Encryption

```bash
aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

### 3.3 Enforce HTTPS and Deny HTTP

```bash
aws s3api put-bucket-policy \
  --bucket my-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyHTTP",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::my-bucket",
          "arn:aws:s3:::my-bucket/*"
        ],
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      }
    ]
  }'
```

### 3.4 Enable Versioning and Lifecycle Rules

```bash
# Enable versioning
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled

# Add lifecycle rule to expire old versions
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-bucket \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "ExpireOldVersions",
      "Status": "Enabled",
      "NoncurrentVersionExpiration": {"NoncurrentDays": 90}
    }]
  }'
```

---

## 4. Compute (EC2) Mitigation Strategies

### 4.1 Enforce IMDSv2

```bash
# On new instance
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type t2.micro \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled

# On existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-12345678 \
  --http-tokens required \
  --http-endpoint enabled
```

### 4.2 Enable EBS Encryption by Default

```bash
# Enable EBS encryption by default for all new volumes in region
aws ec2 enable-ebs-encryption-by-default

# Verify
aws ec2 get-ebs-encryption-by-default
```

### 4.3 Use Systems Manager Instead of SSH

```bash
# Start Session Manager session (no SSH/bastion needed)
aws ssm start-session --target i-12345678

# Run command via SSM
aws ssm send-command \
  --instance-ids i-12345678 \
  --document-name AWS-RunShellScript \
  --parameters commands='["sudo yum update -y"]'
```

### 4.4 EC2 Security Hardening Checklist

```bash
# 1. Update all packages
sudo yum update -y  # Amazon Linux
# sudo apt-get update && sudo apt-get upgrade -y  # Ubuntu

# 2. Enable automatic security updates
sudo yum install -y yum-cron
sudo systemctl enable yum-cron && sudo systemctl start yum-cron

# 3. Install and configure fail2ban
sudo yum install -y epel-release fail2ban
sudo systemctl enable fail2ban && sudo systemctl start fail2ban

# 4. Disable root SSH login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# 5. Configure audit daemon
sudo yum install -y audit
sudo systemctl enable auditd && sudo systemctl start auditd
```

---

## 5. Logging & Monitoring Mitigation Strategies

### 5.1 Enable CloudTrail

```bash
# Create S3 bucket for CloudTrail logs
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws s3api create-bucket \
  --bucket my-cloudtrail-logs-${ACCOUNT_ID} \
  --region us-east-1

# Create multi-region CloudTrail
aws cloudtrail create-trail \
  --name my-cloudtrail \
  --s3-bucket-name my-cloudtrail-logs-${ACCOUNT_ID} \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events

# Start logging
aws cloudtrail start-logging --name my-cloudtrail
```

### 5.2 CloudWatch Security Alarms

```bash
# Alarm: Root account usage
aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountUsage \
  --metric-name RootAccountUsage \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:SecurityAlerts

# Alarm: Unauthorized API calls
aws cloudwatch put-metric-alarm \
  --alarm-name UnauthorizedAPICalls \
  --metric-name UnauthorizedAttemptCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:SecurityAlerts
```

### 5.3 Enable AWS Config

```bash
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/ConfigRole \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

# Enable managed security rules
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "restricted-ssh",
  "Source": {"Owner": "AWS", "SourceIdentifier": "INCOMING_SSH_DISABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"}
}'
```

### 5.4 Enable GuardDuty

```bash
# Enable GuardDuty (30-day free trial)
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Create EventBridge rule for high-severity findings
aws events put-rule \
  --name GuardDutyHighSeverity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {"severity": [{"numeric": [">=", 7]}]}
  }' \
  --state ENABLED
```

---

## Mitigation Priority Matrix

| Risk | Effort | Impact | Priority |
|------|--------|--------|----------|
| Enable MFA | Low | High | 🔴 Do First |
| Block S3 Public Access | Low | High | 🔴 Do First |
| Enable CloudTrail | Low | High | 🔴 Do First |
| Fix Open Security Groups | Low | High | 🔴 Do First |
| Enforce IMDSv2 | Low | Medium | 🟠 Do Soon |
| Encrypt EBS Volumes | Medium | High | 🟠 Do Soon |
| Enable VPC Flow Logs | Low | Medium | 🟠 Do Soon |
| Enable GuardDuty | Low | High | 🟠 Do Soon |
| Rotate Access Keys | Medium | Medium | 🟡 Plan |
| Enable AWS Config | Medium | Medium | 🟡 Plan |
| Network NACL Hardening | High | Medium | 🟡 Plan |
| IAM Access Analyzer | Low | Medium | 🟢 When Ready |
