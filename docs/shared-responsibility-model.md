# 🔐 AWS Shared Responsibility Model

## Overview

The AWS Shared Responsibility Model defines the division of security
responsibilities between AWS and the customer. Understanding this model is
**foundational** to building secure cloud infrastructure.

```
┌─────────────────────────────────────────────────────────────┐
│                  CUSTOMER RESPONSIBILITY                      │
│                  "Security IN the Cloud"                      │
├─────────────────────────────────────────────────────────────┤
│  Customer Data                                                │
│  Platform, Applications, Identity & Access Management        │
│  Operating System, Network & Firewall Configuration          │
│  Client-Side Encryption & Server-Side Encryption             │
│  Network Traffic Protection (Encryption, Integrity)          │
├─────────────────────────────────────────────────────────────┤
│                  AWS RESPONSIBILITY                           │
│                  "Security OF the Cloud"                      │
├─────────────────────────────────────────────────────────────┤
│  Compute | Storage | Database | Networking                   │
│  AWS Global Infrastructure                                    │
│  Regions | Availability Zones | Edge Locations               │
└─────────────────────────────────────────────────────────────┘
```

---

## AWS Responsibilities ("Security OF the Cloud")

AWS is responsible for protecting the infrastructure that runs all services
offered in the AWS Cloud.

### Physical Infrastructure

| Component | AWS Responsibility |
|-----------|-------------------|
| Data Centers | Physical security, access controls, surveillance |
| Hardware | Server hardware maintenance and replacement |
| Networking | Core network infrastructure, DDoS protection at infrastructure level |
| Facilities | Power, cooling, fire suppression |

### Managed Service Security

For **fully managed services**, AWS takes on MORE responsibility:

| Service Type | AWS Manages | Customer Manages |
|-------------|-------------|-----------------|
| **RDS** | OS patching, backups, replication | Access controls, data, encryption settings |
| **Lambda** | Runtime patches, execution environment | Function code, IAM permissions |
| **S3** | Storage infrastructure, durability | Bucket policies, ACLs, encryption choice |
| **DynamoDB** | Database engine, hardware | Table access, encryption, backup config |
| **EKS** | Control plane, etcd | Worker nodes, pod security, networking |

---

## Customer Responsibilities ("Security IN the Cloud")

Customers are responsible for everything they put IN the cloud.

### 1. Identity and Access Management (IAM)

Customer MUST:
```
✓ Create strong IAM policies (least privilege)
✓ Enable MFA for all users, especially root
✓ Rotate access keys regularly (every 90 days)
✓ Avoid using root account for daily tasks
✓ Use IAM roles instead of long-term credentials
✓ Review and audit permissions regularly
```

**Example: Least Privilege IAM Policy**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSpecificS3BucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::my-app-bucket/*"
    },
    {
      "Sid": "AllowListBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-app-bucket"
    }
  ]
}
```

### 2. Operating System and Application Patching

For EC2 instances, customers must:
- Apply OS security patches promptly
- Update application dependencies
- Configure OS-level firewalls (iptables, firewalld)
- Harden the OS (disable unused services, ports)
- Implement host-based intrusion detection

AWS Systems Manager Patch Manager can automate OS patching:

```bash
# Create a patch baseline
aws ssm create-patch-baseline \
  --name "AmazonLinux2-Security-Baseline" \
  --operating-system AMAZON_LINUX_2 \
  --approval-rules '{"PatchRules":[{"PatchFilterGroup":{"PatchFilters":[{"Key":"CLASSIFICATION","Values":["Security","Bugfix"]}]},"ApproveAfterDays":0}]}'
```

### 3. Network Configuration

Customers control:
- Security Group rules (virtual firewall)
- Network ACLs (subnet-level controls)
- VPC routing tables
- VPN and Direct Connect configurations
- Application-level encryption (TLS/SSL)

**Security Group Best Practices:**

```bash
# ❌ BAD - Open to the world
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# ✅ GOOD - Restricted to specific IP
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345 \
  --protocol tcp --port 22 --cidr 203.0.113.10/32
```

### 4. Data Protection

| Data State | Customer Responsibility |
|------------|------------------------|
| In Transit | Enforce TLS/HTTPS; use ACM certificates |
| At Rest | Enable S3 encryption, EBS encryption, RDS encryption |
| In Use | Application-level encryption for sensitive data |
| Backups | Configure automated backups; test restoration |

### 5. Logging and Monitoring

Customers must enable and monitor:
```
✓ CloudTrail    - API call logging (who did what, when)
✓ VPC Flow Logs - Network traffic logging
✓ CloudWatch    - Metrics, alarms, and dashboards
✓ Config        - Resource configuration change tracking
✓ GuardDuty     - Threat detection (ML-powered)
✓ Security Hub  - Centralized security findings
```

---

## Responsibility by Service Type

### Infrastructure Services (IaaS) — EC2, VPC

```
AWS Manages:          Customer Manages:
├── Hardware          ├── Guest OS
├── Hypervisor        ├── Applications
├── Physical Network  ├── Data
└── Data Center       ├── Security Groups
                      ├── IAM Policies
                      ├── Encryption
                      └── OS Patching
```

### Container Services — ECS, EKS

```
AWS Manages:          Customer Manages:
├── Control Plane     ├── Container Images
├── Managed Nodes     ├── Pod Security Policies
└── Networking Infra  ├── Application Code
                      ├── IAM Roles for Service Accounts
                      └── Network Policies
```

### Serverless (PaaS) — Lambda, S3, DynamoDB

```
AWS Manages:          Customer Manages:
├── Infrastructure    ├── Function/Application Code
├── OS/Runtime        ├── IAM Permissions
├── Scaling           ├── Data Classification
└── Availability      ├── Encryption Key Management
                      └── API/Application Security
```

---

## Key Takeaways

> 💡 The more managed the service, the more AWS handles — but you're **ALWAYS**
> responsible for your data and access controls.

| Always YOUR Responsibility | Always AWS Responsibility |
|---------------------------|--------------------------|
| IAM policies and users | Physical security |
| Your application code | Hypervisor security |
| Data classification | Global network infrastructure |
| Access key management | Core service availability |
| Encryption decisions | Hardware maintenance |

---

## Additional Resources

- [AWS Shared Responsibility Model Official Page](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
