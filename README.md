# devsecops-aws-pipeline

A production-grade DevSecOps pipeline for AWS infrastructure — shift-left security scanning integrated into CI/CD from day one.

## What this does

- Scans CloudFormation templates with **Checkov** before any deployment
- Scans container images with **Trivy** for CVEs and misconfigurations
- Validates IAM policies for least-privilege with **boto3** compliance scripts
- Enforces HIPAA/SOC2-aligned controls on AWS infrastructure
- Runs all checks in **GitHub Actions** on every pull request

## Architecture

```
Pull Request
    │
    ▼
GitHub Actions
    ├── Checkov → scans CloudFormation templates
    ├── Trivy   → scans Dockerfile + built image
    ├── boto3   → validates IAM permission boundaries
    └── Results → PR comment with findings
         │
         ▼ (all checks pass)
    Merge allowed
         │
         ▼
    CloudFormation deploy (staging → prod)
```

## Repository structure

```
.
├── .github/workflows/
│   └── security-scan.yml       # Main CI/CD security pipeline
├── cloudformation/
│   ├── vpc.yaml                 # Hardened VPC with flow logs
│   ├── eks-cluster.yaml         # EKS cluster with security groups
│   └── iam-roles.yaml           # IAM roles with permission boundaries
├── docker/
│   └── Dockerfile               # Hardened base image example
├── scripts/
│   └── iam_compliance_check.py  # boto3 IAM compliance validator
└── README.md
```

## Stack

| Tool | Purpose |
|------|---------|
| Checkov | IaC static analysis (CloudFormation, Dockerfile) |
| Trivy | Container + OS CVE scanning |
| GitHub Actions | CI/CD orchestration |
| AWS CloudFormation | Infrastructure as Code |
| Python boto3 | AWS compliance automation |
| AWS EKS | Container orchestration |

## Running locally

```bash
# Install Checkov
pip install checkov

# Scan CloudFormation templates
checkov -d cloudformation/ --framework cloudformation

# Install Trivy
brew install aquasecurity/trivy/trivy   # macOS
# or
sudo apt install trivy                   # Ubuntu

# Scan Dockerfile
trivy config docker/Dockerfile

# Scan built image
docker build -t myapp:latest docker/
trivy image myapp:latest

# Run IAM compliance check
pip install boto3
python scripts/iam_compliance_check.py
```

## Checkov results (sample)

```
Passed checks: 34, Failed checks: 0, Skipped checks: 2

cloudformation/vpc.yaml
  Passed: CKV_AWS_2   - Ensure ALB protocol is HTTPS
  Passed: CKV_AWS_91  - Ensure VPC flow logging is enabled
  Passed: CKV_AWS_130 - Ensure VPC subnets do not assign public IP by default

cloudformation/iam-roles.yaml
  Passed: CKV_AWS_107 - Ensure IAM policies do not have admin permissions
  Passed: CKV_AWS_108 - Ensure IAM policies do not allow data exfiltration
  Passed: CKV_AWS_111 - Ensure IAM policies do not allow write access without constraints
```

## Background

Built from experience running HIPAA-compliant AWS infrastructure at Baxter International — where 99.99% uptime and regulatory compliance were non-negotiable. This pipeline applies those same standards to any AWS environment.

---

**Author:** Akhil Adarsh Suryapagula  
**LinkedIn:** [linkedin.com/in/akhiladarsh](https://linkedin.com/in/akhiladarsh)  
**Website:** [akhiladarsh.com](https://akhiladarsh.com)
