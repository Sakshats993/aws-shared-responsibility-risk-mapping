# 📋 AWS Risk Assessment Template

**Assessment Date:** _______________
**Assessor:** _______________
**AWS Account ID:** _______________
**AWS Region(s):** _______________
**Assessment Scope:** _______________

---

## 1. Scope Definition

### In-Scope Services
- [ ] IAM (Users, Roles, Policies)
- [ ] EC2 (Instances, Security Groups, EBS)
- [ ] S3 (Buckets, Policies, ACLs)
- [ ] VPC (Subnets, Routing, NACLs, Flow Logs)
- [ ] RDS (Instances, Snapshots)
- [ ] CloudTrail
- [ ] CloudWatch
- [ ] Lambda
- [ ] EKS/ECS
- [ ] Other: _______________

### Out-of-Scope
- _______________

---

## 2. Risk Scoring Methodology

### Likelihood Score (1–5)

| Score | Likelihood | Description |
|-------|-----------|-------------|
| 5 | Almost Certain | Expected to occur in most circumstances |
| 4 | Likely | Will probably occur |
| 3 | Possible | Might occur at some point |
| 2 | Unlikely | Not expected to occur |
| 1 | Rare | May occur only in exceptional circumstances |

### Impact Score (1–5)

| Score | Impact | Description |
|-------|--------|-------------|
| 5 | Critical | Catastrophic; complete system/data compromise |
| 4 | Major | Significant data breach or service outage |
| 3 | Moderate | Limited data exposure or service degradation |
| 2 | Minor | Minimal impact; easily contained |
| 1 | Negligible | Little to no impact |

### Risk Score = Likelihood × Impact

| Risk Score | Rating |
|------------|--------|
| 20–25 | 🔴 Critical |
| 12–19 | 🟠 High |
| 6–11 | 🟡 Medium |
| 1–5 | 🟢 Low |

---

## 3. Findings Log

| ID | Category | Finding | Likelihood | Impact | Score | Severity | Owner | Due Date | Status |
|----|----------|---------|------------|--------|-------|----------|-------|----------|--------|
| F001 | IAM | | | | | | | | |
| F002 | Networking | | | | | | | | |
| F003 | Storage | | | | | | | | |
| F004 | Compute | | | | | | | | |
| F005 | Logging | | | | | | | | |

---

## 4. IAM Assessment

### Root Account
- [ ] Root account has no access keys
- [ ] Root account has MFA enabled
- [ ] Root account is not used for daily operations
- **Finding:** _______________
- **Risk Score:** ___

### IAM Users

- Total users: ___
- Users without MFA: ___
- Users with old access keys (>90 days): ___
- Users with no recent activity (>90 days): ___

| User | MFA | Key Age (days) | Last Activity |
|------|-----|---------------|---------------|
| | Y/N | | |

### IAM Policies
- [ ] No policies with `Action: *` and `Resource: *`
- [ ] No inline policies with admin permissions
- [ ] Access Analyzer enabled
- **Finding:** _______________

---

## 5. Networking Assessment

### Security Groups

- Total security groups: ___
- SGs with 0.0.0.0/0 on port 22: ___
- SGs with 0.0.0.0/0 on port 3389: ___
- SGs with 0.0.0.0/0 on database ports: ___

| SG ID | Port | Rule | Risk |
|-------|------|------|------|
| | | | |

### VPC Configuration
- [ ] Custom VPC used (not default)
- [ ] Public/private subnet separation
- [ ] VPC Flow Logs enabled
- [ ] NACLs configured (not just default)
- **Finding:** _______________

---

## 6. Storage Assessment

### S3 Buckets

- Total buckets: ___
- Public buckets: ___
- Unencrypted buckets: ___
- Buckets without versioning: ___
- Buckets without access logging: ___

| Bucket | Public | Encrypted | Versioning | Logging |
|--------|--------|-----------|------------|---------|
| | Y/N | Y/N | Y/N | Y/N |

### EBS Volumes
- Total volumes: ___
- Unencrypted volumes: ___
- Unattached volumes: ___
- **Finding:** _______________

---

## 7. Compute Assessment

### EC2 Instances

- Total instances: ___
- Instances in public subnet: ___
- Instances with IMDSv1 (not enforcing v2): ___
- Instances without patching: ___

| Instance ID | Subnet | IMDSv2 | SG Issues |
|-------------|--------|--------|-----------|
| | Public/Private | Y/N | Y/N |

### RDS
- [ ] No publicly accessible RDS instances
- [ ] RDS encryption enabled
- [ ] Multi-AZ enabled for production
- [ ] Automated backups configured
- **Finding:** _______________

---

## 8. Logging Assessment

### CloudTrail
- [ ] CloudTrail enabled in all regions
- [ ] Multi-region trail configured
- [ ] Log file validation enabled
- [ ] Logs sent to CloudWatch
- [ ] S3 bucket for logs is not public
- **Finding:** _______________

### CloudWatch
- [ ] CloudWatch alarms for root account use
- [ ] CloudWatch alarms for unauthorized API calls
- [ ] CloudWatch alarms for security group changes
- **Finding:** _______________

### GuardDuty
- [ ] GuardDuty enabled
- [ ] Findings reviewed regularly
- [ ] Integration with Security Hub
- **Finding:** _______________

---

## 9. Risk Register

| ID | Risk Description | Likelihood | Impact | Score | Severity | Mitigation | Owner | ETA |
|----|-----------------|------------|--------|-------|----------|------------|-------|-----|
| R001 | | | | | | | | |
| R002 | | | | | | | | |

---

## 10. Recommendations Summary

### Immediate Actions (Critical/High — Do within 72 hours)
1. _______________
2. _______________
3. _______________

### Short-Term (Medium — Do within 30 days)
1. _______________
2. _______________

### Long-Term (Low — Do within 90 days)
1. _______________
2. _______________

---

## 11. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Assessor | | | |
| Technical Lead | | | |
| Security Manager | | | |

**Next Review Date:** _______________
