#!/usr/bin/env python3
"""
S3 Bucket Security Checker
===========================
Author: aws-shared-responsibility-risk-mapping
Description: Detailed S3 bucket security assessment checking public access,
             encryption, versioning, logging, SSL enforcement, and CORS.

Usage:
    python s3-bucket-checker.py
    python s3-bucket-checker.py --bucket my-specific-bucket
    python s3-bucket-checker.py --profile my-profile

Requirements:
    pip install boto3
    AWS CLI configured: aws configure
"""

import boto3
import json
import datetime
import argparse
import sys
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


# ─────────────────────────────────────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────────────────────────────────────
class Colors:
    RED    = '\033[91m'
    ORANGE = '\033[33m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'


SEVERITY_ICON = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
    'INFO':     'ℹ️ ',
}


# ─────────────────────────────────────────────────────────────────────────────
# Bucket Checker
# ─────────────────────────────────────────────────────────────────────────────

def check_bucket(s3, name):
    """Run all security checks against a single bucket. Returns list of issues."""
    issues = []

    # 1 ── Public Access Block ───────────────────────────────────────────────
    try:
        pub = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
        missing = [
            k for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
            if not pub.get(k)
        ]
        if missing:
            issues.append({
                'severity': 'CRITICAL',
                'check': 'Public Access Block',
                'detail': f'These settings are OFF: {", ".join(missing)}',
                'fix': 'Enable all four S3 Block Public Access settings.',
            })
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            issues.append({
                'severity': 'CRITICAL',
                'check': 'Public Access Block',
                'detail': 'No public access block configuration exists',
                'fix': 'Enable S3 Block Public Access on this bucket.',
            })

    # 2 ── ACL ───────────────────────────────────────────────────────────────
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        public_grants = [
            g for g in acl.get('Grants', [])
            if g.get('Grantee', {}).get('URI', '') in (
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
            )
        ]
        if public_grants:
            issues.append({
                'severity': 'CRITICAL',
                'check': 'Bucket ACL',
                'detail': 'Bucket ACL grants access to AllUsers or AuthenticatedUsers',
                'fix': 'Remove public ACL grants; set Object Ownership to "Bucket owner enforced".',
            })
    except ClientError as e:
        print(f"  Warning: Cannot check ACL for {name}: {e}")

    # 3 ── Default Encryption ────────────────────────────────────────────────
    try:
        enc = s3.get_bucket_encryption(Bucket=name)
        rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        alg   = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '') if rules else ''
        if alg not in ('AES256', 'aws:kms'):
            issues.append({
                'severity': 'HIGH',
                'check': 'Encryption',
                'detail': f'Unsupported or missing algorithm: "{alg}"',
                'fix': 'Set default encryption to SSE-S3 (AES256) or SSE-KMS.',
            })
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            issues.append({
                'severity': 'HIGH',
                'check': 'Encryption',
                'detail': 'No default encryption configured',
                'fix': 'Enable SSE-S3 or SSE-KMS default encryption.',
            })

    # 4 ── Versioning ────────────────────────────────────────────────────────
    try:
        ver = s3.get_bucket_versioning(Bucket=name)
        if ver.get('Status') != 'Enabled':
            issues.append({
                'severity': 'MEDIUM',
                'check': 'Versioning',
                'detail': f'Versioning status: {ver.get("Status", "Disabled")}',
                'fix': 'Enable versioning to recover from accidental deletion or ransomware.',
            })
    except ClientError as e:
        print(f"  Warning: Cannot check versioning for {name}: {e}")

    # 5 ── Access Logging ────────────────────────────────────────────────────
    try:
        log = s3.get_bucket_logging(Bucket=name)
        if 'LoggingEnabled' not in log:
            issues.append({
                'severity': 'MEDIUM',
                'check': 'Access Logging',
                'detail': 'Server access logging is disabled',
                'fix': 'Enable server access logging to a dedicated log bucket.',
            })
    except ClientError as e:
        print(f"  Warning: Cannot check logging for {name}: {e}")

    # 6 ── HTTPS Enforcement ─────────────────────────────────────────────────
    https_enforced = False
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
        for stmt in policy.get('Statement', []):
            cond = stmt.get('Condition', {})
            if (stmt.get('Effect') == 'Deny'
                    and 'Bool' in cond
                    and cond['Bool'].get('aws:SecureTransport') in ['false', False]):
                https_enforced = True
                break
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            pass  # No policy → not enforced

    if not https_enforced:
        issues.append({
            'severity': 'HIGH',
            'check': 'HTTPS Enforcement',
            'detail': 'Bucket policy does not deny HTTP requests',
            'fix': 'Add a Deny statement with Condition: aws:SecureTransport=false.',
        })

    # 7 ── MFA Delete ────────────────────────────────────────────────────────
    try:
        ver = s3.get_bucket_versioning(Bucket=name)
        if ver.get('MFADelete', 'Disabled') != 'Enabled':
            issues.append({
                'severity': 'LOW',
                'check': 'MFA Delete',
                'detail': 'MFA Delete is not enabled',
                'fix': 'Enable MFA Delete for sensitive buckets (requires root credentials).',
            })
    except ClientError:
        pass  # Already handled above

    return issues


def build_session(profile):
    try:
        session = boto3.Session(profile_name=profile)
        sts     = session.client('sts')
        identity = sts.get_caller_identity()
        print(f"\n{Colors.GREEN}✅  Authenticated: {identity['Arn']}{Colors.RESET}")
        return session
    except ProfileNotFound:
        print(f"{Colors.RED}ERROR: Profile '{profile}' not found.{Colors.RESET}")
        sys.exit(1)
    except NoCredentialsError:
        print(f"{Colors.RED}ERROR: No credentials found. Run 'aws configure'.{Colors.RESET}")
        sys.exit(1)
    except ClientError as e:
        print(f"{Colors.RED}ERROR: {e}{Colors.RESET}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='S3 Bucket Security Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python s3-bucket-checker.py
  python s3-bucket-checker.py --bucket my-app-data
  python s3-bucket-checker.py --profile prod --output s3_report.json
        """,
    )
    parser.add_argument('--bucket',  default=None,  help='Scan a specific bucket only.')
    parser.add_argument('--profile', default=None,  help='AWS CLI profile.')
    parser.add_argument('--output',  default=None,  help='Output JSON filename.')
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}{Colors.CYAN}🪣  S3 Bucket Security Checker{Colors.RESET}")
    print(f"{'─'*60}")

    session = build_session(args.profile)
    s3 = session.client('s3')

    # Get bucket list
    try:
        all_buckets = s3.list_buckets().get('Buckets', [])
    except ClientError as e:
        print(f"{Colors.RED}ERROR listing buckets: {e}{Colors.RESET}")
        sys.exit(1)

    if args.bucket:
        buckets = [b for b in all_buckets if b['Name'] == args.bucket]
        if not buckets:
            print(f"{Colors.RED}Bucket '{args.bucket}' not found in this account.{Colors.RESET}")
            sys.exit(1)
    else:
        buckets = all_buckets

    print(f"\n{Colors.BLUE}🔍 Scanning {len(buckets)} bucket(s)...{Colors.RESET}\n")

    results     = {}
    total_issues = 0

    for bucket in buckets:
        name   = bucket['Name']
        issues = check_bucket(s3, name)
        results[name] = issues
        total_issues += len(issues)

        if issues:
            print(f"  {Colors.ORANGE}⚠️  {name}{Colors.RESET}")
            for issue in issues:
                icon = SEVERITY_ICON.get(issue['severity'], '❓')
                print(f"     {icon} [{issue['severity']}] {issue['check']}")
                print(f"        {Colors.YELLOW}Issue:{Colors.RESET} {issue['detail']}")
                print(f"        {Colors.GREEN}Fix:  {Colors.RESET} {issue['fix']}")
        else:
            print(f"  {Colors.GREEN}✅  {name} (0 issues){Colors.RESET}")

    # Summary
    secure_count    = sum(1 for issues in results.values() if not issues)
    attention_count = len(buckets) - secure_count

    print(f"\n{'─'*60}")
    print(f"{Colors.BOLD}📊 Summary:{Colors.RESET}")
    print(f"   Total buckets:  {len(buckets)}")
    print(f"   {Colors.GREEN}Fully secure:   {secure_count}{Colors.RESET}")
    print(f"   {Colors.ORANGE}Need attention: {attention_count}{Colors.RESET}")
    print(f"   Total issues:   {total_issues}")

    # Save JSON report
    ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = args.output or f"s3_security_report_{ts}.json"

    report = {
        'generated_at': datetime.datetime.utcnow().isoformat() + 'Z',
        'total_buckets': len(buckets),
        'secure_buckets': secure_count,
        'buckets_with_issues': attention_count,
        'total_issues': total_issues,
        'buckets': {
            name: {
                'issue_count': len(issues),
                'issues': issues,
            }
            for name, issues in results.items()
        },
    }

    with open(filename, 'w') as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"\n{Colors.CYAN}💾 Detailed report saved to: {Colors.BOLD}{filename}{Colors.RESET}\n")


if __name__ == '__main__':
    main()
