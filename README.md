# aws-recon

One command to find out what an AWS CLI profile can actually see.

```
aws lambda list-functions --profile ABC
aws s3 ls --profile ABC
aws ec2 describe-instances --profile ABC
... one command per service, forever ...
```

vs.

```
python3 aws_recon.py --profile ABC
```

## Why

- **[Pacu](https://github.com/RhinoSecurityLabs/pacu)** is powerful but module-based — you run each service check one at a time from its interactive shell.
- **[enumerate-iam](https://github.com/andresriancho/enumerate-iam)** does a single-shot scan, but only accepts raw `--access-key`/`--secret-key`, so it can't be used with STS session-token creds, `assume-role` profiles, or SSO profiles without manually pulling the keys out first.

`aws_recon.py` instead opens a `boto3.Session(profile_name=...)`, which parses `~/.aws/credentials` and `~/.aws/config` **exactly the way the `aws` CLI binary does** — including:

- Long-term access key / secret key profiles
- Temporary credentials (`aws_access_key_id` + `aws_secret_access_key` + `aws_session_token`)
- `role_arn` + `source_profile` assume-role chains
- `credential_process` profiles
- `sso_*` profiles (after `aws sso login`)

So the only flag you ever need is `--profile`, same as the AWS CLI itself.

## Install

```bash
git clone https://github.com/Abhineet0904/aws-recon.git
cd AWSrecon
pip install -r requirements.txt --break-system-packages   # Kali/Debian needs this flag
```

## Usage

```bash
# Basic scan, current default region for the profile
python3 aws_recon.py --profile ABC

# Scan every enabled region (needs ec2:DescribeRegions, else falls back)
python3 aws_recon.py --profile ABC --all-regions

# Specific regions only
python3 aws_recon.py --profile ABC --region us-east-1 --region eu-west-1

# Limit to specific services
python3 aws_recon.py --profile ABC --services s3,iam,lambda,ec2

# Show every resource found (default truncates to 5 per check)
python3 aws_recon.py --profile ABC --full

# Save full machine-readable output too
python3 aws_recon.py --profile ABC --json report.json

# See every service key it knows how to check
python3 aws_recon.py --list-services
```

## What it does

1. Calls `sts:GetCallerIdentity` first, so you immediately know which account/identity/ARN the profile resolves to (and fails fast with a clear error if the creds are missing/expired).
2. Fans out ~50 read-only `List*` / `Describe*` / `Get*` calls across ~40 services (IAM, S3, EC2, Lambda, RDS, DynamoDB, ECS, EKS, CloudFormation, SNS, SQS, CloudWatch Logs, KMS, Secrets Manager, SSM, ELBv2, Auto Scaling, API Gateway, CloudTrail, Config, Redshift, ElastiCache, EFS, SageMaker, Glue, Athena, CodeBuild, CodePipeline, ECR, GuardDuty, WAFv2, ACM, Backup, Transfer, Batch, Step Functions, EventBridge, Firehose, OpenSearch, Route 53, CloudFront, SES, Organizations, and more) using a thread pool.
3. Buckets every check into **Accessible (with resources)**, **Accessible (empty)**, **Access Denied**, and **Error/Not Applicable**, printing the ARN (or best available identifier) of every resource it finds.
4. Optionally dumps the whole thing as JSON for feeding into other tooling.

## What it does *not* do

- It never calls a mutating API (no `Create*`, `Put*`, `Delete*`, `Update*`). It is read-only enumeration.
- It doesn't brute-force or guess credentials — it only reports what the profile you already configured can see.
- It isn't exhaustive for every AWS service that exists (AWS has 300+). It covers the ones people actually need during an authorized assessment or an access audit. PRs adding more `SERVICE_CHECKS` entries are welcome — the format is documented in-line in `aws_recon.py`.

## ⚠️ Use responsibly

Only run this against AWS accounts/credentials you own or are explicitly authorized to test. Enumeration is read-only but can still trigger CloudTrail/GuardDuty alerting, and unauthorized access to systems you don't own is illegal in most jurisdictions regardless of which API calls you make.
