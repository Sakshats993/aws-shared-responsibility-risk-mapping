# ☁️ AWS Cloud Security Risk Categories

## Overview

This document catalogs common AWS security risks organized by category,
with severity ratings and initial mitigation guidance.

---

## Risk Severity Scale

| Level | Color | CVSS Score | Description |
|-------|-------|------------|-------------|
| Critical | 🔴 | 9.0–10.0 | Immediate action required; active exploitation risk |
| High | 🟠 | 7.0–8.9 | Fix within 24–72 hours |
| Medium | 🟡 | 4.0–6.9 | Fix within 30 days |
| Low | 🟢 | 0.1–3.9 | Fix within 90 days |
| Informational | ℹ️ | 0.0 | Best practice recommendation |

---

## Category 1: Identity and Access Management (IAM)

### IAM-001: Root Account Active Use

- **Severity:** 🔴 Critical
- **Description:** AWS root account has active access keys or is used for daily operations.
- **Risk:** Full account compromise if credentials are stolen.
- **Detection:**
  ```bash
  aws iam get-account-summary | grep -i root
  aws iam list-virtual-mfa-devices
  ```
- **Remediation:** Delete root access keys; enable MFA on root account.

---

### IAM-002: Missing MFA on IAM Users

- **Severity:** 🟠 High
- **Description:** IAM users with console access don't have MFA enabled.
- **Risk:** Account takeover via password compromise.
- **Detection:**
  ```bash
  aws iam generate-credential-report
  aws iam get-credential-report
  # Check mfa_active column
  ```
- **Remediation:** Enforce MFA via IAM policy.

---

### IAM-003: Overly Permissive IAM Policies

- **Severity:** 🟠 High
- **Description:** Policies with `"Action": "*"` or `"Resource": "*"`.
- **Risk:** Privilege escalation; lateral movement after compromise.
- **Detection:**
  ```bash
  aws iam list-policies --scope Local
  aws iam get-policy-version --policy-arn <arn> --version-id v1
  ```
- **Remediation:** Apply least privilege; use IAM Access Analyzer.

---

### IAM-004: Old or Unused Access Keys

- **Severity:** 🟡 Medium
- **Description:** Access keys older than 90 days or last used > 90 days ago.
- **Risk:** Credential exposure from old or forgotten keys.
- **Detection:**
  ```bash
  aws iam list-access-keys
  aws iam get-access-key-last-used --access-key-id <key-id>
  ```
- **Remediation:** Rotate keys; delete unused keys.

---

### IAM-005: Inline Policies Instead of Managed Policies

- **Severity:** ℹ️ Informational
- **Description:** Using inline policies rather than managed policies.
- **Risk:** Harder to audit and manage at scale.
- **Remediation:** Migrate to AWS managed or customer-managed policies.

---

## Category 2: Networking

### NET-001: Security Groups Open to 0.0.0.0/0

- **Severity:** 🔴 Critical (for admin ports) / 🟠 High (for others)
- **Description:** Security groups allowing unrestricted access on sensitive ports.
- **High-Risk Ports:**
  ```
  22   - SSH
  3389 - RDP
  1433 - MSSQL
  3306 - MySQL
  5432 - PostgreSQL
  27017 - MongoDB
  6379 - Redis
  ```
- **Detection:**
  ```bash
  aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'
  ```
- **Remediation:** Restrict to specific IPs or CIDR ranges.

---

### NET-002: No VPC Flow Logs

- **Severity:** 🟡 Medium
- **Description:** VPC Flow Logs are not enabled.
- **Risk:** No network traffic visibility for forensics or anomaly detection.
- **Detection:**
  ```bash
  aws ec2 describe-flow-logs
  ```
- **Remediation:** Enable VPC Flow Logs to CloudWatch or S3.

---

### NET-003: Default VPC in Use

- **Severity:** 🟡 Medium
- **Description:** Resources deployed in the AWS default VPC.
- **Risk:** Default VPC has permissive settings; not designed for production.
- **Remediation:** Create custom VPCs with proper segmentation.

---

### NET-004: No Network ACLs (Default Allow-All)

- **Severity:** 🟡 Medium
- **Description:** Network ACLs set to default (allow all traffic).
- **Risk:** No subnet-level traffic filtering as defense-in-depth.
- **Remediation:** Configure restrictive NACLs as second layer of defense.

---

### NET-005: Public Subnets for Backend Services

- **Severity:** 🟠 High
- **Description:** Database or application servers in public subnets.
- **Risk:** Direct internet exposure of sensitive services.
- **Remediation:** Move backends to private subnets; use NAT Gateway for egress.

---

## Category 3: Storage (S3)

### S3-001: Public S3 Bucket

- **Severity:** 🔴 Critical
- **Description:** S3 bucket is publicly accessible (via ACL or bucket policy).
- **Risk:** Sensitive data exposure; major compliance violation.
- **Detection:**
  ```bash
  aws s3api get-bucket-acl --bucket <bucket-name>
  aws s3api get-bucket-policy --bucket <bucket-name>
  aws s3api get-public-access-block --bucket <bucket-name>
  ```
- **Remediation:** Enable S3 Block Public Access at account and bucket level.

---

### S3-002: No Default Encryption

- **Severity:** 🟠 High
- **Description:** S3 bucket does not have default encryption enabled.
- **Risk:** Data stored unencrypted at rest.
- **Detection:**
  ```bash
  aws s3api get-bucket-encryption --bucket <bucket-name>
  ```
- **Remediation:** Enable SSE-S3 or SSE-KMS encryption.

---

### S3-003: No Versioning Enabled

- **Severity:** 🟡 Medium
- **Description:** S3 bucket versioning is disabled.
- **Risk:** Cannot recover from accidental deletion or ransomware.
- **Remediation:** Enable versioning; configure lifecycle rules for cost management.

---

### S3-004: No Access Logging

- **Severity:** 🟡 Medium
- **Description:** S3 server access logging is disabled.
- **Risk:** No audit trail for data access.
- **Remediation:** Enable server access logging to a dedicated log bucket.

---

### S3-005: HTTP Access Allowed

- **Severity:** 🟠 High
- **Description:** Bucket policy does not enforce HTTPS.
- **Risk:** Data in transit unencrypted; susceptible to MITM attacks.
- **Remediation:** Add bucket policy denying HTTP (`aws:SecureTransport: false`).

```json
{
  "Sid": "DenyHTTP",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::bucket-name/*"],
  "Condition": {
    "Bool": {"aws:SecureTransport": "false"}
  }
}
```

---

## Category 4: Compute (EC2)

### EC2-001: No IMDSv2 Enforcement

- **Severity:** 🟠 High
- **Description:** EC2 instances allow IMDSv1 (no session token required).
- **Risk:** SSRF attacks can steal instance metadata and credentials.
- **Detection:**
  ```bash
  aws ec2 describe-instances \
    --query 'Reservations[].Instances[?MetadataOptions.HttpTokens!=`required`]'
  ```
- **Remediation:** Enforce IMDSv2 (`http_tokens = required`).

---

### EC2-002: Unencrypted EBS Volumes

- **Severity:** 🟠 High
- **Description:** EBS volumes are not encrypted.
- **Risk:** Data exposure if volume is detached and accessed.
- **Detection:**
  ```bash
  aws ec2 describe-volumes \
    --query 'Volumes[?Encrypted==`false`]'
  ```
- **Remediation:** Enable EBS encryption by default; encrypt existing volumes.

---

### EC2-003: Publicly Accessible RDS

- **Severity:** 🔴 Critical
- **Description:** RDS instance is publicly accessible.
- **Risk:** Database exposed to internet scanning and brute force.
- **Detection:**
  ```bash
  aws rds describe-db-instances \
    --query 'DBInstances[?PubliclyAccessible==`true`]'
  ```
- **Remediation:** Set `PubliclyAccessible = false`; use private subnets.

---

### EC2-004: No Automated Patching

- **Severity:** 🟡 Medium
- **Description:** EC2 instances have no automated patch management.
- **Risk:** Known vulnerabilities exploited over time.
- **Remediation:** Use AWS Systems Manager Patch Manager.

---

### EC2-005: Unused/Unattached EBS Volumes

- **Severity:** ℹ️ Informational
- **Description:** EBS volumes not attached to any instance.
- **Risk:** Cost waste; potential data exposure.
- **Remediation:** Delete or archive; snapshot if needed.

---

## Category 5: Logging and Monitoring

### LOG-001: CloudTrail Disabled

- **Severity:** 🔴 Critical
- **Description:** AWS CloudTrail is not enabled in one or more regions.
- **Risk:** No audit trail for API calls; cannot investigate incidents.
- **Detection:**
  ```bash
  aws cloudtrail describe-trails
  aws cloudtrail get-trail-status --name <trail-name>
  ```
- **Remediation:** Enable CloudTrail in all regions; send to CloudWatch Logs.

---

### LOG-002: CloudTrail Log Validation Disabled

- **Severity:** 🟠 High
- **Description:** CloudTrail log file validation is not enabled.
- **Risk:** Logs could be tampered with without detection.
- **Remediation:** Enable log file validation (`--enable-log-file-validation`).

---

### LOG-003: No CloudWatch Alarms

- **Severity:** 🟡 Medium
- **Description:** No CloudWatch alarms configured for security events.
- **Risk:** Security events go undetected.
- **Remediation:** Set up alarms for root login, failed auth, SG changes, etc.

---

### LOG-004: GuardDuty Disabled

- **Severity:** 🟠 High
- **Description:** Amazon GuardDuty is not enabled.
- **Risk:** No ML-based threat detection for the account.
- **Remediation:** Enable GuardDuty (30-day free trial available).

---

## Risk Summary Matrix

| Category | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info |
|----------|------------|---------|----------|--------|---------|
| IAM | 1 | 2 | 1 | 0 | 1 |
| Networking | 1 | 2 | 2 | 0 | 0 |
| Storage (S3) | 1 | 2 | 2 | 0 | 0 |
| Compute (EC2) | 1 | 3 | 1 | 0 | 1 |
| Logging | 1 | 2 | 2 | 0 | 0 |
| **TOTAL** | **5** | **11** | **8** | **0** | **2** |
