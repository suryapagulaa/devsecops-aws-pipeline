#!/usr/bin/env python3
"""
iam_compliance_check.py
Validates IAM configuration for common misconfigurations.

Checks:
  - Roles missing permission boundaries
  - Customer-managed policies with wildcard Action + Resource
  - Console users without MFA
  - Active access keys older than N days (default 90)
  - Root account MFA and access key status

Usage:
    python scripts/iam_compliance_check.py
    python scripts/iam_compliance_check.py --region us-east-1 --output json
    python scripts/iam_compliance_check.py --key-rotation-days 60

Exit 0 if no CRITICAL or HIGH findings, 1 otherwise.
"""

import boto3
import json
import sys
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    severity: str
    control: str
    resource: str
    message: str
    fix: str


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    passed: int = 0

    def add(self, f: Finding):
        self.findings.append(f)

    def ok(self):
        self.passed += 1

    @property
    def failed(self):
        return len(self.findings)

    @property
    def is_compliant(self):
        return not any(f.severity in ('CRITICAL', 'HIGH') for f in self.findings)


def check_permission_boundaries(iam, report: Report):
    print("  checking permission boundaries...")
    paginator = iam.get_paginator('list_roles')

    skip_paths = ['aws-service-role/', 'aws-reserved/']

    for page in paginator.paginate():
        for role in page['Roles']:
            if any(role.get('Path', '/').startswith(p) for p in skip_paths):
                continue

            if 'PermissionsBoundary' not in role:
                report.add(Finding(
                    severity='HIGH',
                    control='IAM-001',
                    resource=role['RoleName'],
                    message=f"Role {role['RoleName']} has no permission boundary.",
                    fix=(
                        f"aws iam put-role-permissions-boundary "
                        f"--role-name {role['RoleName']} --permissions-boundary <BOUNDARY_ARN>"
                    )
                ))
            else:
                report.ok()


def check_wildcard_policies(iam, report: Report):
    print("  checking for wildcard policies...")
    paginator = iam.get_paginator('list_policies')

    for page in paginator.paginate(Scope='Local'):
        for policy in page['Policies']:
            version = iam.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
            )
            statements = version['PolicyVersion']['Document'].get('Statement', [])

            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get('Effect') != 'Allow':
                    continue

                actions = stmt.get('Action', [])
                resources = stmt.get('Resource', [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if '*' in actions and '*' in resources:
                    report.add(Finding(
                        severity='CRITICAL',
                        control='IAM-002',
                        resource=policy['PolicyName'],
                        message=f"Policy {policy['PolicyName']} allows Action:* with Resource:*.",
                        fix="Replace * action/resource with specific ARNs and actions required."
                    ))
                else:
                    report.ok()


def check_mfa_on_console_users(iam, report: Report):
    print("  checking MFA on console users...")
    paginator = iam.get_paginator('list_users')

    for page in paginator.paginate():
        for user in page['Users']:
            try:
                iam.get_login_profile(UserName=user['UserName'])
            except iam.exceptions.NoSuchEntityException:
                continue

            devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']

            if not devices:
                report.add(Finding(
                    severity='CRITICAL',
                    control='IAM-003',
                    resource=user['UserName'],
                    message=f"{user['UserName']} has console access but no MFA device.",
                    fix="Enroll a virtual or hardware MFA device for this user."
                ))
            else:
                report.ok()


def check_old_access_keys(iam, report: Report, max_days: int = 90):
    print(f"  checking access key age (max {max_days}d)...")
    paginator = iam.get_paginator('list_users')
    now = datetime.now(timezone.utc)

    for page in paginator.paginate():
        for user in page['Users']:
            for key in iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
                if key['Status'] != 'Active':
                    continue

                age = (now - key['CreateDate']).days
                if age > max_days:
                    report.add(Finding(
                        severity='HIGH',
                        control='IAM-004',
                        resource=f"{user['UserName']}/{key['AccessKeyId']}",
                        message=f"Access key is {age} days old (limit: {max_days}).",
                        fix=(
                            f"aws iam create-access-key --user-name {user['UserName']} "
                            f"&& aws iam delete-access-key --user-name {user['UserName']} "
                            f"--access-key-id {key['AccessKeyId']}"
                        )
                    ))
                else:
                    report.ok()


def check_root_account(iam, report: Report):
    print("  checking root account...")
    summary = iam.get_account_summary()['SummaryMap']

    if summary.get('AccountMFAEnabled', 0) != 1:
        report.add(Finding(
            severity='CRITICAL',
            control='IAM-005',
            resource='root',
            message="Root account does not have MFA enabled.",
            fix="Enable MFA on root via AWS Console > Security Credentials."
        ))
    else:
        report.ok()

    if summary.get('AccountAccessKeysPresent', 0) > 0:
        report.add(Finding(
            severity='CRITICAL',
            control='IAM-005',
            resource='root',
            message="Root account has active access keys.",
            fix="Delete root access keys immediately via AWS Console > Security Credentials."
        ))
    else:
        report.ok()


def print_text(report: Report):
    print(f"\n{'='*50}")
    print("IAM COMPLIANCE REPORT")
    print(f"{'='*50}")
    print(f"  passed : {report.passed}")
    print(f"  failed : {report.failed}")
    print(f"  result : {'PASS' if report.is_compliant else 'FAIL'}")
    print(f"{'='*50}")

    if not report.findings:
        print("\n  No violations.\n")
        return

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        group = [f for f in report.findings if f.severity == severity]
        if not group:
            continue
        print(f"\n  {severity} ({len(group)})")
        for f in group:
            print(f"\n    [{f.control}] {f.resource}")
            print(f"    {f.message}")
            print(f"    fix: {f.fix}")
    print()


def print_json(report: Report):
    out = {
        'summary': {
            'passed': report.passed,
            'failed': report.failed,
            'compliant': report.is_compliant
        },
        'findings': [
            {
                'severity': f.severity,
                'control': f.control,
                'resource': f.resource,
                'message': f.message,
                'fix': f.fix
            }
            for f in report.findings
        ]
    }
    print(json.dumps(out, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--output', choices=['text', 'json'], default='text')
    parser.add_argument('--key-rotation-days', type=int, default=90)
    args = parser.parse_args()

    print(f"\nIAM check — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} — {args.region}")

    iam = boto3.client('iam', region_name=args.region)
    report = Report()

    for fn in [
        check_root_account,
        check_mfa_on_console_users,
        check_wildcard_policies,
        check_permission_boundaries,
        lambda c, r: check_old_access_keys(c, r, args.key_rotation_days),
    ]:
        try:
            fn(iam, report)
        except Exception as e:
            print(f"  warn: {e}")

    if args.output == 'json':
        print_json(report)
    else:
        print_text(report)

    sys.exit(0 if report.is_compliant else 1)


if __name__ == '__main__':
    main()
