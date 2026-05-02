# ✅ AWS Security Checklist

> Use this checklist for regular AWS security reviews. Check off items as
> you verify/implement them. Items are organized by category and priority.

**Last Updated:** 2026-04-28
**Account ID:** _______________
**Reviewed By:** _______________
**Review Date:** _______________

---

## 🔑 IAM (Identity & Access Management)

### Root Account
- [ ] **[CRITICAL]** Root account has no active access keys
- [ ] **[CRITICAL]** Root account has MFA (hardware key recommended)
- [ ] **[HIGH]** Root account is not used for any operations
- [ ] **[HIGH]** Root account email has a secure, monitored inbox
- [ ] **[MEDIUM]** Root account recovery options are documented

### IAM Users
- [ ] **[CRITICAL]** All IAM users with console access have MFA enabled
- [ ] **[HIGH]** No user has AdministratorAccess unless absolutely required
- [ ] **[HIGH]** No shared IAM user accounts (1 user = 1 person)
- [ ] **[HIGH]** Access keys rotated within last 90 days
- [ ] **[MEDIUM]** Inactive users (90+ days) are deactivated or deleted
- [ ] **[MEDIUM]** Credential report reviewed regularly
- [ ] **[LOW]** All users have tags (Owner, Team, Purpose)

### IAM Policies
- [ ] **[CRITICAL]** No `"Action": "*"` with `"Resource": "*"` in any policy
- [ ] **[HIGH]** Policies follow least-privilege principle
- [ ] **[HIGH]** IAM Access Analyzer is enabled
- [ ] **[MEDIUM]** Managed policies used instead of inline policies
- [ ] **[MEDIUM]** Service Control Policies (SCPs) configured (if using Organizations)
- [ ] **[LOW]** Unused policies are removed

### IAM Roles
- [ ] **[HIGH]** EC2 instances use IAM roles (not access keys)
- [ ] **[HIGH]** Lambda functions use IAM roles with minimal permissions
- [ ] **[HIGH]** Cross-account roles have external ID conditions
- [ ] **[MEDIUM]** Role trust policies are reviewed regularly
- [ ] **[LOW]** Role names follow naming convention

### Password Policy
- [ ] **[HIGH]** Minimum password length ≥ 14 characters
- [ ] **[HIGH]** Password complexity required (uppercase, lowercase, numbers, symbols)
- [ ] **[MEDIUM]** Password expiration set (90 days)
- [ ] **[MEDIUM]** Password reuse prevention (last 24 passwords)
- [ ] **[LOW]** Users can change their own passwords

---

## 🌐 Networking

### VPC Configuration
- [ ] **[HIGH]** Custom VPCs used instead of default VPC
- [ ] **[HIGH]** Default VPC is empty or deleted
- [ ] **[HIGH]** Public/private subnet architecture implemented
- [ ] **[MEDIUM]** VPC CIDR ranges don't overlap with on-premises

### Security Groups
- [ ] **[CRITICAL]** No security group allows 0.0.0.0/0 on port 22 (SSH)
- [ ] **[CRITICAL]** No security group allows 0.0.0.0/0 on port 3389 (RDP)
- [ ] **[HIGH]** No security group allows 0.0.0.0/0 on database ports
- [ ] **[HIGH]** Security groups use specific IP ranges, not 0.0.0.0/0
- [ ] **[MEDIUM]** Security groups have descriptive names and tags
- [ ] **[MEDIUM]** Unused security groups are removed
- [ ] **[LOW]** Security groups reference other SGs for internal traffic

### Network ACLs
- [ ] **[MEDIUM]** NACLs configured as second layer of defense
- [ ] **[MEDIUM]** Egress filtering configured
- [ ] **[LOW]** Default NACL is not modified (use custom NACLs)

### Flow Logs
- [ ] **[HIGH]** VPC Flow Logs enabled for all VPCs
- [ ] **[MEDIUM]** Flow logs sent to CloudWatch or S3
- [ ] **[MEDIUM]** Retention period defined for flow logs
- [ ] **[LOW]** Flow logs are monitored for anomalies

### Other Network
- [ ] **[HIGH]** No publicly exposed services without WAF (for web traffic)
- [ ] **[MEDIUM]** AWS Shield Standard enabled (auto for all accounts)
- [ ] **[LOW]** Route 53 DNSSEC enabled for critical domains

---

## 🪣 Storage (S3)

### Public Access
- [ ] **[CRITICAL]** S3 Block Public Access enabled at account level
- [ ] **[CRITICAL]** S3 Block Public Access enabled on all buckets
- [ ] **[CRITICAL]** No bucket has public ACL or public bucket policy
- [ ] **[HIGH]** S3 Object Ownership set to "Bucket owner enforced"

### Encryption
- [ ] **[HIGH]** Default encryption enabled on all S3 buckets
- [ ] **[HIGH]** Bucket policy denies HTTP (requires HTTPS)
- [ ] **[MEDIUM]** KMS-managed keys used for sensitive buckets
- [ ] **[LOW]** Key rotation enabled for KMS keys

### Access Control
- [ ] **[HIGH]** S3 bucket policies are reviewed and documented
- [ ] **[MEDIUM]** Versioning enabled on important buckets
- [ ] **[MEDIUM]** Object Lock configured for compliance buckets
- [ ] **[MEDIUM]** Cross-origin resource sharing (CORS) properly configured
- [ ] **[LOW]** Access logging enabled for sensitive buckets

### Lifecycle and Compliance
- [ ] **[MEDIUM]** Lifecycle rules configured to manage storage costs
- [ ] **[MEDIUM]** Intelligent Tiering used for variable-access data
- [ ] **[LOW]** Replication configured for disaster recovery if needed

---

## 💻 Compute (EC2)

### Instance Configuration
- [ ] **[HIGH]** EC2 instances use IMDSv2 (HttpTokens=required)
- [ ] **[HIGH]** No EC2 instances in public subnets (use ALB + private)
- [ ] **[HIGH]** Instances accessed via SSM Session Manager (not SSH from internet)
- [ ] **[MEDIUM]** Instance types are right-sized (not over-provisioned)
- [ ] **[LOW]** Instances have proper tags (Name, Environment, Owner)

### EBS Volumes
- [ ] **[HIGH]** EBS encryption by default enabled for the region
- [ ] **[HIGH]** All EBS volumes are encrypted
- [ ] **[MEDIUM]** EBS snapshots are encrypted
- [ ] **[MEDIUM]** EBS snapshots are not public
- [ ] **[LOW]** Unattached EBS volumes are reviewed and deleted

### AMIs
- [ ] **[HIGH]** Custom AMIs are hardened (CIS benchmark)
- [ ] **[MEDIUM]** AMIs are private (not public unless intentional)
- [ ] **[MEDIUM]** AMIs are regularly updated with patches
- [ ] **[LOW]** Outdated AMIs are deregistered

### Patching
- [ ] **[HIGH]** OS patching automated via SSM Patch Manager
- [ ] **[HIGH]** Security patches applied within 30 days
- [ ] **[MEDIUM]** Patch compliance reports reviewed monthly

### RDS
- [ ] **[CRITICAL]** RDS instances are not publicly accessible
- [ ] **[HIGH]** RDS encryption at rest enabled
- [ ] **[HIGH]** RDS in private subnets
- [ ] **[MEDIUM]** Multi-AZ enabled for production databases
- [ ] **[MEDIUM]** Automated backups configured (≥7 days retention)
- [ ] **[MEDIUM]** RDS minor version auto-upgrade enabled
- [ ] **[LOW]** RDS parameter groups reviewed for security settings

---

## 📊 Logging & Monitoring

### CloudTrail
- [ ] **[CRITICAL]** CloudTrail enabled in all regions
- [ ] **[HIGH]** Multi-region trail configured
- [ ] **[HIGH]** CloudTrail log file validation enabled
- [ ] **[HIGH]** CloudTrail S3 bucket is not public
- [ ] **[MEDIUM]** CloudTrail integrated with CloudWatch Logs
- [ ] **[MEDIUM]** Log retention period defined (min 1 year for compliance)
- [ ] **[LOW]** CloudTrail advanced event selectors configured

### CloudWatch
- [ ] **[HIGH]** Alarm: Root account usage (any activity)
- [ ] **[HIGH]** Alarm: Unauthorized API calls (>5 in 5 min)
- [ ] **[HIGH]** Alarm: Security group changes
- [ ] **[HIGH]** Alarm: MFA device changes
- [ ] **[MEDIUM]** Alarm: IAM policy changes
- [ ] **[MEDIUM]** Alarm: S3 bucket policy changes
- [ ] **[MEDIUM]** Alarm: CloudTrail disabled
- [ ] **[LOW]** Dashboard created for security metrics

### Threat Detection
- [ ] **[HIGH]** AWS GuardDuty enabled in all regions
- [ ] **[HIGH]** GuardDuty findings reviewed and remediated
- [ ] **[MEDIUM]** AWS Security Hub enabled
- [ ] **[MEDIUM]** AWS Inspector enabled for EC2/container scanning
- [ ] **[LOW]** GuardDuty integrated with SIEM (if applicable)

### Configuration Management
- [ ] **[HIGH]** AWS Config enabled in all regions
- [ ] **[HIGH]** AWS Config rules for security (restricted-ssh, s3-public-prohibited, etc.)
- [ ] **[MEDIUM]** AWS Config aggregator configured (multi-account)
- [ ] **[LOW]** AWS Config remediation actions configured

---

## 🔐 Data Protection

### Encryption
- [ ] **[HIGH]** KMS key rotation enabled (for customer-managed keys)
- [ ] **[HIGH]** Sensitive data identified and classified
- [ ] **[MEDIUM]** AWS Macie enabled for S3 sensitive data discovery
- [ ] **[MEDIUM]** Secrets Manager used (not environment variables) for secrets
- [ ] **[LOW]** Secrets Manager rotation configured

### Backup and Recovery
- [ ] **[HIGH]** AWS Backup configured for critical resources
- [ ] **[HIGH]** Backup restoration tested periodically
- [ ] **[MEDIUM]** RPO and RTO defined and documented
- [ ] **[LOW]** Cross-region backups configured for DR

---

## ✅ Checklist Summary

| Category | Total Items | Checked | Completion % |
|----------|-------------|---------|-------------|
| IAM | 22 | ___ | ___ |
| Networking | 18 | ___ | ___ |
| Storage (S3) | 14 | ___ | ___ |
| Compute | 20 | ___ | ___ |
| Logging | 18 | ___ | ___ |
| Data Protection | 8 | ___ | ___ |
| **TOTAL** | **100** | **___** | **___** |

### Score Interpretation

| Score | Rating |
|-------|--------|
| 90–100% | 🟢 Excellent |
| 75–89% | 🟡 Good |
| 50–74% | 🟠 Needs Work |
| <50% | 🔴 Critical Attention Needed |
