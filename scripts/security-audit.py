#!/usr/bin/env python3
"""
AWS Security Audit Script
=========================
Author: aws-shared-responsibility-risk-mapping
Description: Audits AWS account for common security misconfigurations
             across Security Groups, S3, IAM, CloudTrail, EBS, and IMDSv2.

Usage:
    python security-audit.py
    python security-audit.py --region us-west-2
    python security-audit.py --region us-east-1 --region us-west-2
    python security-audit.py --profile my-profile

Requirements:
    pip install boto3
    AWS CLI configured: aws configure
"""

import boto3
import json
from datetime import datetime, UTC
import argparse
import sys
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


# ─────────────────────────────────────────────────────────────────────────────
# ANSI Color Codes for Terminal Output
# ─────────────────────────────────────────────────────────────────────────────
class Colors:
    RED = '\033[91m'
    ORANGE = '\033[33m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def color_severity(severity):
    """Return colored severity string."""
    colors = {
        'CRITICAL': Colors.RED + Colors.BOLD + '🔴 CRITICAL' + Colors.RESET,
        'HIGH':     Colors.ORANGE + '🟠 HIGH' + Colors.RESET,
        'MEDIUM':   Colors.YELLOW + '🟡 MEDIUM' + Colors.RESET,
        'LOW':      Colors.GREEN + '🟢 LOW' + Colors.RESET,
        'INFO':     Colors.BLUE + 'ℹ️  INFO' + Colors.RESET,
    }
    return colors.get(severity, severity)


# ─────────────────────────────────────────────────────────────────────────────
# Finding Class
# ─────────────────────────────────────────────────────────────────────────────
class Finding:
    def __init__(self, severity, resource_type, resource_id, issue,
                 recommendation, category, region='global'):
        self.severity = severity
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.issue = issue
        self.recommendation = recommendation
        self.category = category
        self.region = region
        self.timestamp = datetime.now(UTC).isoformat()

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'severity': self.severity,
            'category': self.category,
            'resource_type': self.resource_type,
            'resource': self.resource_id,
            'issue': self.issue,
            'recommendation': self.recommendation,
            'region': self.region,
        }

    def __str__(self):
        return (
            f"\n[{color_severity(self.severity)}] "
            f"{Colors.BOLD}{self.resource_id}{Colors.RESET}\n"
            f"  Category:   {self.category}\n"
            f"  Resource:   {self.resource_type}\n"
            f"  Region:     {self.region}\n"
            f"  Issue:      {self.issue}\n"
            f"  Fix:        {self.recommendation}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Audit Functions
# ─────────────────────────────────────────────────────────────────────────────

def check_security_groups(session, region):
    """Check EC2 Security Groups for overly permissive rules."""
    findings = []
    print(f"\n{Colors.BLUE}🔍 Checking Security Groups in {region}...{Colors.RESET}")

    ec2 = session.client('ec2', region_name=region)

    # High-risk ports that should never be open to 0.0.0.0/0
    dangerous_ports = {
        22:    ('SSH',                    'CRITICAL'),
        3389:  ('RDP',                    'CRITICAL'),
        2375:  ('Docker (unencrypted)',   'CRITICAL'),
        1433:  ('MSSQL',                  'HIGH'),
        3306:  ('MySQL',                  'HIGH'),
        5432:  ('PostgreSQL',             'HIGH'),
        27017: ('MongoDB',                'HIGH'),
        6379:  ('Redis',                  'HIGH'),
        9200:  ('Elasticsearch',          'HIGH'),
        9300:  ('Elasticsearch (cluster)','HIGH'),
        2376:  ('Docker TLS',             'HIGH'),
    }

    try:
        paginator = ec2.get_paginator('describe_security_groups')
        sg_ids_with_findings = set()

        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                sg_id   = sg['GroupId']
                sg_name = sg.get('GroupName', 'Unknown')

                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port   = rule.get('ToPort',   65535)
                    protocol  = rule.get('IpProtocol', '-1')

                    # ── IPv4 checks ──
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            if protocol == '-1':          # all traffic
                                sg_ids_with_findings.add(sg_id)
                                findings.append(Finding(
                                    severity='CRITICAL',
                                    resource_type='Security Group',
                                    resource_id=f"{sg_id} ({sg_name})",
                                    issue='Allows ALL traffic from 0.0.0.0/0',
                                    recommendation='Remove allow-all rule; restrict to specific ports and IPs.',
                                    category='Networking',
                                    region=region,
                                ))
                            else:
                                for port, (service, sev) in dangerous_ports.items():
                                    if from_port <= port <= to_port:
                                        sg_ids_with_findings.add(sg_id)
                                        findings.append(Finding(
                                            severity=sev,
                                            resource_type='Security Group',
                                            resource_id=f"{sg_id} ({sg_name})",
                                            issue=f'Allows 0.0.0.0/0 on port {port} ({service})',
                                            recommendation=(
                                                f'Restrict {service} to specific IP ranges '
                                                f'or use AWS SSM Session Manager instead of SSH.'
                                            ),
                                            category='Networking',
                                            region=region,
                                        ))

                    # ── IPv6 checks ──
                    for ip_range in rule.get('Ipv6Ranges', []):
                        if ip_range.get('CidrIpv6') == '::/0':
                            if protocol == '-1':
                                sg_ids_with_findings.add(sg_id)
                                findings.append(Finding(
                                    severity='CRITICAL',
                                    resource_type='Security Group',
                                    resource_id=f"{sg_id} ({sg_name})",
                                    issue='Allows ALL traffic from ::/0 (IPv6)',
                                    recommendation='Remove allow-all IPv6 rule.',
                                    category='Networking',
                                    region=region,
                                ))

    except ClientError as e:
        print(f"  {Colors.RED}ERROR: {e}{Colors.RESET}")

    print(f"  Found {len(findings)} security group issue(s)")
    return findings


def check_s3_buckets(session):
    """Check S3 Buckets for public access and encryption issues."""
    findings = []
    print(f"\n{Colors.BLUE}🔍 Checking S3 Buckets...{Colors.RESET}")

    s3 = session.client('s3')

    try:
        response = s3.list_buckets()
        buckets  = response.get('Buckets', [])
        print(f"  Found {len(buckets)} bucket(s)")

        for bucket in buckets:
            name = bucket['Name']

            # 1 ── Public Access Block ──────────────────────────────────────
            try:
                pub = s3.get_public_access_block(Bucket=name)
                cfg = pub['PublicAccessBlockConfiguration']
                if not all([
                    cfg.get('BlockPublicAcls'),
                    cfg.get('IgnorePublicAcls'),
                    cfg.get('BlockPublicPolicy'),
                    cfg.get('RestrictPublicBuckets'),
                ]):
                    findings.append(Finding(
                        severity='CRITICAL',
                        resource_type='S3 Bucket',
                        resource_id=name,
                        issue='Not all public-access-block settings are enabled',
                        recommendation='Enable all four S3 Block Public Access settings.',
                        category='Storage',
                    ))
            except ClientError as e:
                code = e.response['Error']['Code']
                if code == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append(Finding(
                        severity='CRITICAL',
                        resource_type='S3 Bucket',
                        resource_id=name,
                        issue='No public access block configuration exists',
                        recommendation='Enable S3 Block Public Access on this bucket.',
                        category='Storage',
                    ))

            # 2 ── Default Encryption ───────────────────────────────────────
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append(Finding(
                        severity='HIGH',
                        resource_type='S3 Bucket',
                        resource_id=name,
                        issue='Default encryption is not enabled',
                        recommendation='Enable SSE-S3 or SSE-KMS default encryption.',
                        category='Storage',
                    ))

            # 3 ── Versioning ───────────────────────────────────────────────
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                if ver.get('Status') != 'Enabled':
                    findings.append(Finding(
                        severity='MEDIUM',
                        resource_type='S3 Bucket',
                        resource_id=name,
                        issue='Bucket versioning is not enabled',
                        recommendation='Enable versioning to protect against accidental deletion and ransomware.',
                        category='Storage',
                    ))
            except ClientError as e:
                print(f"  Warning: Could not check versioning for {name}: {e}")

            # 4 ── Access Logging ───────────────────────────────────────────
            try:
                log_cfg = s3.get_bucket_logging(Bucket=name)
                if 'LoggingEnabled' not in log_cfg:
                    findings.append(Finding(
                        severity='MEDIUM',
                        resource_type='S3 Bucket',
                        resource_id=name,
                        issue='Server access logging is not enabled',
                        recommendation='Enable server access logging to a dedicated log bucket.',
                        category='Storage',
                    ))
            except ClientError as e:
                print(f"  Warning: Could not check logging for {name}: {e}")

            # 5 ── HTTPS Enforcement ────────────────────────────────────────
            try:
                policy_str = s3.get_bucket_policy(Bucket=name)['Policy']
                policy     = json.loads(policy_str)
                has_deny_http = False
                for stmt in policy.get('Statement', []):
                    cond = stmt.get('Condition', {})
                    if (stmt.get('Effect') == 'Deny'
                            and 'Bool' in cond
                            and cond['Bool'].get('aws:SecureTransport') in ['false', False]):
                        has_deny_http = True
                        break
                if not has_deny_http:
                    findings.append(Finding(
                        severity='HIGH',
                        resource_type='S3 Bucket',
                        resource_id=name,
                        issue='Bucket policy does not enforce HTTPS',
                        recommendation='Add a Deny statement for aws:SecureTransport=false.',
                        category='Storage',
                    ))
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    findings.append(Finding(
                        severity='HIGH',
                        resource_type='S3 Bucket',
                        resource_id=name,
                        issue='No bucket policy — HTTPS not enforced',
                        recommendation='Add a bucket policy that denies HTTP requests.',
                        category='Storage',
                    ))

    except ClientError as e:
        print(f"  {Colors.RED}ERROR listing buckets: {e}{Colors.RESET}")

    print(f"  Found {len(findings)} S3 issue(s)")
    return findings


def check_iam(session):
    """Check IAM users, MFA, access key age, and root account."""
    findings = []
    print(f"\n{Colors.BLUE}🔍 Checking IAM Users...{Colors.RESET}")

    iam = session.client('iam')
    now = datetime.now(UTC)
    KEY_AGE_WARN = 90    # days → medium
    KEY_AGE_CRIT = 180   # days → high

    # ── Root Account ──────────────────────────────────────────────────────
    try:
        summary = iam.get_account_summary()['SummaryMap']

        if not summary.get('AccountMFAEnabled', 0):
            findings.append(Finding(
                severity='CRITICAL',
                resource_type='Root Account',
                resource_id='root',
                issue='Root account does not have MFA enabled',
                recommendation='Enable hardware MFA on root account immediately.',
                category='IAM',
            ))

        if summary.get('AccountAccessKeysPresent', 0):
            findings.append(Finding(
                severity='CRITICAL',
                resource_type='Root Account',
                resource_id='root',
                issue='Root account has active access keys',
                recommendation='Delete root access keys; use IAM roles for programmatic access.',
                category='IAM',
            ))
    except ClientError as e:
        print(f"  {Colors.RED}ERROR checking root account: {e}{Colors.RESET}")

    # ── IAM Users ─────────────────────────────────────────────────────────
    try:
        paginator = iam.get_paginator('list_users')
        users = [u for page in paginator.paginate() for u in page['Users']]
        print(f"  Found {len(users)} IAM user(s)")

        for user in users:
            username = user['UserName']

            # MFA check
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
            if not mfa_devices:
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except ClientError as e:
                    has_console = e.response['Error']['Code'] != 'NoSuchEntity'

                if has_console:
                    findings.append(Finding(
                        severity='HIGH',
                        resource_type='IAM User',
                        resource_id=username,
                        issue=f'User "{username}" has console access but no MFA',
                        recommendation='Enable MFA for this user and enforce via IAM policy.',
                        category='IAM',
                    ))

            # Access key age
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                key_id  = key['AccessKeyId']
                status  = key['Status']
                age     = (now - key['CreateDate']).days

                if status == 'Active' and age > KEY_AGE_WARN:
                    sev = 'HIGH' if age > KEY_AGE_CRIT else 'MEDIUM'
                    findings.append(Finding(
                        severity=sev,
                        resource_type='IAM Access Key',
                        resource_id=f"{username}/{key_id}",
                        issue=f'Access key is {age} days old (threshold: {KEY_AGE_WARN} days)',
                        recommendation='Rotate access keys every 90 days.',
                        category='IAM',
                    ))

                if status == 'Inactive' and age > 30:
                    findings.append(Finding(
                        severity='LOW',
                        resource_type='IAM Access Key',
                        resource_id=f"{username}/{key_id}",
                        issue=f'Inactive access key has existed for {age} days',
                        recommendation='Delete inactive access keys to reduce attack surface.',
                        category='IAM',
                    ))

    except ClientError as e:
        print(f"  {Colors.RED}ERROR listing users: {e}{Colors.RESET}")

    print(f"  Found {len(findings)} IAM issue(s)")
    return findings


def check_cloudtrail(session, regions):
    """Check CloudTrail configuration globally (correct multi-region handling)."""
    findings = []
    print(f"\n{Colors.BLUE}🔍 Checking CloudTrail...{Colors.RESET}")

    try:
        # IMPORTANT: Do NOT hardcode region
        ct = session.client('cloudtrail', region_name='us-east-1')

        # FIX: includeShadowTrails=True (detect multi-region trails)
        response = ct.describe_trails(includeShadowTrails=True)
        trails = response.get('trailList', [])

        if not trails:
            findings.append(Finding(
                severity='CRITICAL',
                resource_type='CloudTrail',
                resource_id='Account',
                issue='No CloudTrail trails configured',
                recommendation='Create a multi-region CloudTrail.',
                category='Logging',
            ))
            print("  Found 1 CloudTrail issue(s)")
            return findings

        valid_trail_found = False

        for trail in trails:
            name = trail['Name']
            arn = trail['TrailARN']

            try:
                status = ct.get_trail_status(Name=arn)
            except ClientError as e:
                print(f"  Warning: Could not get status for {name}: {e}")
                continue

            is_logging = status.get('IsLogging', False)
            is_multi_region = trail.get('IsMultiRegionTrail', False)

            if is_logging and is_multi_region:
                valid_trail_found = True

            if not is_logging:
                findings.append(Finding(
                    severity='CRITICAL',
                    resource_type='CloudTrail',
                    resource_id=name,
                    issue='CloudTrail exists but logging is DISABLED',
                    recommendation=f'Run: aws cloudtrail start-logging --name {name}',
                    category='Logging',
                ))

            if not is_multi_region:
                findings.append(Finding(
                    severity='MEDIUM',
                    resource_type='CloudTrail',
                    resource_id=name,
                    issue='CloudTrail is not multi-region',
                    recommendation='Enable multi-region trail for full visibility.',
                    category='Logging',
                ))

            if not trail.get('LogFileValidationEnabled', False):
                findings.append(Finding(
                    severity='HIGH',
                    resource_type='CloudTrail',
                    resource_id=name,
                    issue='Log file validation is not enabled',
                    recommendation=f'Run: aws cloudtrail update-trail --name {name} --enable-log-file-validation',
                    category='Logging',
                ))

        if not valid_trail_found:
            findings.append(Finding(
                severity='CRITICAL',
                resource_type='CloudTrail',
                resource_id='Account',
                issue='No active multi-region CloudTrail with logging enabled',
                recommendation='Ensure at least one multi-region trail is actively logging.',
                category='Logging',
            ))

    except ClientError as e:
        print(f"  {Colors.RED}ERROR checking CloudTrail: {e}{Colors.RESET}")

    print(f"  Found {len(findings)} CloudTrail issue(s)")
    return findings

def check_ebs_encryption(session, region):
    """Check if EBS encryption-by-default is enabled."""
    findings = []
    print(f"\n{Colors.BLUE}🔍 Checking EBS Encryption in {region}...{Colors.RESET}")

    ec2 = session.client('ec2', region_name=region)
    try:
        if not ec2.get_ebs_encryption_by_default().get('EbsEncryptionByDefault', False):
            findings.append(Finding(
                severity='HIGH',
                resource_type='EBS Encryption',
                resource_id=f'Region: {region}',
                issue='EBS encryption-by-default is NOT enabled',
                recommendation='Run: aws ec2 enable-ebs-encryption-by-default --region ' + region,
                category='Compute',
                region=region,
            ))
    except ClientError as e:
        print(f"  {Colors.RED}ERROR: {e}{Colors.RESET}")

    print(f"  Found {len(findings)} EBS encryption issue(s)")
    return findings


def check_imdsv2(session, region):
    """Check if EC2 instances enforce IMDSv2."""
    findings = []
    print(f"\n{Colors.BLUE}🔍 Checking IMDSv2 Enforcement in {region}...{Colors.RESET}")

    ec2 = session.client('ec2', region_name=region)
    count = 0

    try:
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    state = instance['State']['Name']
                    if state in ('terminated', 'shutting-down'):
                        continue
                    count += 1
                    iid      = instance['InstanceId']
                    metadata = instance.get('MetadataOptions', {})

                    if metadata.get('HttpTokens') != 'required':
                        findings.append(Finding(
                            severity='HIGH',
                            resource_type='EC2 Instance',
                            resource_id=iid,
                            issue='Instance does not enforce IMDSv2 (HttpTokens != required)',
                            recommendation=(
                                f'Run: aws ec2 modify-instance-metadata-options '
                                f'--instance-id {iid} --http-tokens required --region {region}'
                            ),
                            category='Compute',
                            region=region,
                        ))
    except ClientError as e:
        print(f"  {Colors.RED}ERROR: {e}{Colors.RESET}")

    print(f"  Checked {count} running instance(s); found {len(findings)} IMDSv2 issue(s)")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(findings):
    """Print a formatted summary of all findings."""
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    counts = {s: 0 for s in severity_order}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = len(findings)
    print(f"\n{'='*60}")
    if total == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}✅  No issues found! Your account looks clean.{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠️   Audit Complete! Found {total} issue(s).{Colors.RESET}\n")
        for sev in severity_order:
            if counts[sev]:
                print(f"  {color_severity(sev)}: {counts[sev]}")

        print(f"\n{'─'*60}")
        for sev in severity_order:
            for f in findings:
                if f.severity == sev:
                    print(f)
    print(f"\n{'='*60}")


def save_report(findings, filename=None):
    """Save findings to a JSON report file."""
    if filename is None:
        ts = datetime.now(UTC).strftime('%Y%m%d_%H%M%S')
        filename = f"security_audit_{ts}.json"

    report = {
        'generated_at': datetime.now(UTC).isoformat(),
        'total_findings': len(findings),
        'summary': {},
        'findings': [f.to_dict() for f in findings],
    }

    for f in findings:
        report['summary'][f.severity] = report['summary'].get(f.severity, 0) + 1

    with open(filename, 'w') as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"\n{Colors.CYAN}💾 Report saved to: {Colors.BOLD}{filename}{Colors.RESET}")
    return filename


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='AWS Security Audit — checks SGs, S3, IAM, CloudTrail, EBS, and IMDSv2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security-audit.py
  python security-audit.py --region us-west-2
  python security-audit.py --region us-east-1 --region eu-west-1
  python security-audit.py --profile my-profile --output my_report.json
        """,
    )
    parser.add_argument(
        '--region', action='append', dest='regions', metavar='REGION',
        help='AWS region to audit (default: us-east-1). Can be specified multiple times.',
    )
    parser.add_argument(
        '--profile', default=None,
        help='AWS CLI profile to use (default: uses environment/default credentials).',
    )
    parser.add_argument(
        '--output', default=None,
        help='Output JSON report filename (default: security_audit_<timestamp>.json).',
    )
    return parser.parse_args()


def main():
    args   = parse_args()
    regions = args.regions or ['us-east-1']

    print(f"\n{Colors.BOLD}{Colors.CYAN}🔐 AWS Security Audit{Colors.RESET}")
    print(f"   Regions : {', '.join(regions)}")
    print(f"   Profile : {args.profile or 'default'}")
    print(f"{'─'*60}")

    # Build boto3 session
    try:
        session = boto3.Session(profile_name=args.profile)
        # Quick credentials check
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        print(f"\n{Colors.GREEN}✅  Authenticated as: {identity['Arn']}{Colors.RESET}")
        print(f"   Account: {identity['Account']}")
    except ProfileNotFound:
        print(f"{Colors.RED}ERROR: AWS profile '{args.profile}' not found.{Colors.RESET}")
        sys.exit(1)
    except NoCredentialsError:
        print(f"{Colors.RED}ERROR: No AWS credentials found. Run 'aws configure'.{Colors.RESET}")
        sys.exit(1)
    except ClientError as e:
        print(f"{Colors.RED}ERROR: {e}{Colors.RESET}")
        sys.exit(1)

    # Run all checks
    all_findings = []
    all_findings += check_iam(session)
    all_findings += check_s3_buckets(session)

    for region in regions:
        all_findings += check_security_groups(session, region)
        all_findings += check_ebs_encryption(session, region)
        all_findings += check_imdsv2(session, region)

    all_findings += check_cloudtrail(session, regions)

    # Output
    print_summary(all_findings)
    save_report(all_findings, filename=args.output)


if __name__ == '__main__':
    main()
