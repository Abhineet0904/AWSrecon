#!/usr/bin/env python3
"""
aws_recon.py - Enumerate every AWS resource/service visible to a given
AWS CLI profile (static keys OR temporary STS session-token creds),
in one shot, using nothing but --profile.

Why this exists
----------------
`aws <service> list-x --profile ABC` has to be run over and over, once per
service, to figure out what a set of credentials can actually see.
Tools like Pacu need you to run modules one at a time; enumerate-iam only
takes raw --access-key/--secret-key (no session-token / SSO / assume-role
profile support). This script instead opens a boto3.Session(profile_name=...)
-- which parses ~/.aws/credentials + ~/.aws/config exactly the way the
`aws` CLI binary does, including aws_session_token, source_profile chains,
role_arn/credential_process, and sso_* profiles -- and then hammers a large
list of read-only "list/describe" calls across ~50 services, catching
AccessDenied vs UnauthorizedOperation vs everything else, so you get a
single consolidated report of what's reachable.

Usage
-----
    python3 aws_recon.py --profile ABC
    python3 aws_recon.py --profile ABC --all-regions
    python3 aws_recon.py --profile ABC --region us-east-1 --region eu-west-1
    python3 aws_recon.py --profile ABC --services s3,iam,lambda,ec2
    python3 aws_recon.py --profile ABC --json out.json
    python3 aws_recon.py --list-services

Legal / use note
-----------------
Only point this at accounts/credentials you own or are explicitly
authorized to test. It only calls read-only List/Describe/Get API
actions -- it never creates, modifies, or deletes anything -- but
enumeration itself can still trip alerting/GuardDuty and should be
covered by the same authorization as any other assessment activity.
"""

import argparse
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import boto3
    import botocore
    from botocore.exceptions import (
        ClientError,
        NoCredentialsError,
        ProfileNotFound,
        EndpointConnectionError,
        BotoCoreError,
    )
except ImportError:
    sys.exit("[!] Missing dependency. Run: pip install boto3 --break-system-packages")

# --------------------------------------------------------------------------
# Terminal colors (Kali-friendly, degrade gracefully if not a tty)
# --------------------------------------------------------------------------
class C:
    G = "\033[92m"   # green  - accessible
    R = "\033[91m"   # red    - denied
    Y = "\033[93m"   # yellow - error / not applicable
    B = "\033[94m"   # blue   - headers
    BOLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def off():
        for a in ("G", "R", "Y", "B", "BOLD", "END"):
            setattr(C, a, "")


# --------------------------------------------------------------------------
# Common field names APIs use for a resource's ARN / unique name.
# We try these in order against every dict item we pull back.
# --------------------------------------------------------------------------
ARN_KEYS = [
    "Arn", "ARN", "arn", "TopicArn", "QueueArn", "FunctionArn", "RoleArn",
    "PolicyArn", "TableArn", "StreamArn", "ClusterArn", "ServiceArn",
    "DBInstanceArn", "LoadBalancerArn", "CertificateArn", "KeyArn",
    "SecretArn", "RepositoryArn", "StateMachineArn", "TrailARN",
    "DomainArn", "PipelineArn", "ProjectArn",
]
NAME_KEYS = [
    "Name", "name", "FunctionName", "TableName", "BucketName", "GroupName",
    "UserName", "RoleName", "PolicyName", "DBInstanceIdentifier",
    "ClusterName", "ClusterIdentifier", "QueueUrl", "TopicArn", "KeyId",
    "SecretId", "StackName", "DomainName", "Id", "InstanceId", "VpcId",
    "GroupId", "VolumeId", "SnapshotId", "RepositoryName",
    "RestApiId", "PipelineName", "ProjectName", "DeliveryStreamName",
    "CacheClusterId", "FileSystemId", "DetectorId", "NotebookInstanceName",
    "WebACLId", "BackupVaultName", "ServerId", "StateMachineArn",
]


def first_present(d, keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k):
            return d[k]
    return None


def extract_identity(item):
    """Pick the best human-readable identifier (prefer ARN, else name/id)."""
    arn = first_present(item, ARN_KEYS)
    if arn:
        return arn
    name = first_present(item, NAME_KEYS)
    if name:
        return name
    return json.dumps(item)[:80]


# --------------------------------------------------------------------------
# Service check definitions.
#   client      : boto3 client name
#   method      : API call to invoke (a List*/Describe*/Get* read-only call)
#   key         : dict key in the response holding the list of resources
#   kwargs      : extra kwargs for the call (e.g. Scope=Local for IAM policies)
#   global_svc  : True if this service is not region-scoped (only queried once)
#   paginate    : if the operation supports a paginator, use it to get everything
# --------------------------------------------------------------------------
SERVICE_CHECKS = [
    # --- Identity / account-wide ---
    dict(service="sts", client="sts", method="get_caller_identity", key=None,
         global_svc=True, label="STS Caller Identity"),

    # --- IAM (global) ---
    dict(service="iam", client="iam", method="list_users", key="Users",
         global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_roles", key="Roles",
         global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_groups", key="Groups",
         global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_policies", key="Policies",
         kwargs={"Scope": "Local"}, global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_instance_profiles",
         key="InstanceProfiles", global_svc=True, paginate=True),
    dict(service="iam", client="iam", method="list_access_keys",
         key="AccessKeyMetadata", global_svc=True, paginate=True,
         label="IAM Access Keys (own user)"),
    dict(service="iam", client="iam", method="get_account_summary",
         key=None, global_svc=True, label="IAM Account Summary"),

    # --- S3 (global) ---
    dict(service="s3", client="s3", method="list_buckets", key="Buckets",
         global_svc=True),

    # --- Regional compute/network/storage ---
    dict(service="ec2", client="ec2", method="describe_instances",
         key="Reservations", nested_key="Instances", paginate=True),
    dict(service="ec2", client="ec2", method="describe_vpcs", key="Vpcs",
         paginate=True),
    dict(service="ec2", client="ec2", method="describe_subnets",
         key="Subnets", paginate=True),
    dict(service="ec2", client="ec2", method="describe_security_groups",
         key="SecurityGroups", paginate=True),
    dict(service="ec2", client="ec2", method="describe_volumes",
         key="Volumes", paginate=True),
    dict(service="ec2", client="ec2", method="describe_snapshots",
         key="Snapshots", kwargs={"OwnerIds": ["self"]}, paginate=True),
    dict(service="ec2", client="ec2", method="describe_key_pairs",
         key="KeyPairs"),
    dict(service="ec2", client="ec2", method="describe_images",
         key="Images", kwargs={"Owners": ["self"]}),

    dict(service="lambda", client="lambda", method="list_functions",
         key="Functions", paginate=True),
    dict(service="rds", client="rds", method="describe_db_instances",
         key="DBInstances", paginate=True),
    dict(service="rds", client="rds", method="describe_db_clusters",
         key="DBClusters", paginate=True),
    dict(service="dynamodb", client="dynamodb", method="list_tables",
         key="TableNames", paginate=True),
    dict(service="ecs", client="ecs", method="list_clusters",
         key="clusterArns", paginate=True),
    dict(service="eks", client="eks", method="list_clusters",
         key="clusters", paginate=True),
    dict(service="cloudformation", client="cloudformation",
         method="list_stacks", key="StackSummaries", paginate=True,
         kwargs={"StackStatusFilter": [
             "CREATE_COMPLETE", "UPDATE_COMPLETE", "ROLLBACK_COMPLETE"]}),
    dict(service="sns", client="sns", method="list_topics",
         key="Topics", paginate=True),
    dict(service="sqs", client="sqs", method="list_queues",
         key="QueueUrls"),
    dict(service="logs", client="logs", method="describe_log_groups",
         key="logGroups", paginate=True),
    dict(service="kms", client="kms", method="list_keys", key="Keys",
         paginate=True),
    dict(service="secretsmanager", client="secretsmanager",
         method="list_secrets", key="SecretList", paginate=True),
    dict(service="ssm", client="ssm", method="describe_parameters",
         key="Parameters", paginate=True),
    dict(service="elbv2", client="elbv2",
         method="describe_load_balancers", key="LoadBalancers",
         paginate=True, label="ELBv2 Load Balancers"),
    dict(service="autoscaling", client="autoscaling",
         method="describe_auto_scaling_groups", key="AutoScalingGroups",
         paginate=True),
    dict(service="apigateway", client="apigateway", method="get_rest_apis",
         key="items"),
    dict(service="cloudtrail", client="cloudtrail",
         method="describe_trails", key="trailList"),
    dict(service="config", client="config",
         method="describe_configuration_recorders",
         key="ConfigurationRecorders"),
    dict(service="redshift", client="redshift",
         method="describe_clusters", key="Clusters", paginate=True),
    dict(service="elasticache", client="elasticache",
         method="describe_cache_clusters", key="CacheClusters",
         paginate=True),
    dict(service="efs", client="efs", method="describe_file_systems",
         key="FileSystems", paginate=True),
    dict(service="sagemaker", client="sagemaker",
         method="list_notebook_instances", key="NotebookInstances",
         paginate=True),
    dict(service="glue", client="glue", method="get_databases",
         key="DatabaseList", paginate=True),
    dict(service="athena", client="athena", method="list_work_groups",
         key="WorkGroups", paginate=True),
    dict(service="codebuild", client="codebuild", method="list_projects",
         key="projects", paginate=True),
    dict(service="codepipeline", client="codepipeline",
         method="list_pipelines", key="pipelines", paginate=True),
    dict(service="ecr", client="ecr", method="describe_repositories",
         key="repositories", paginate=True),
    dict(service="guardduty", client="guardduty", method="list_detectors",
         key="DetectorIds", paginate=True),
    dict(service="wafv2", client="wafv2", method="list_web_acls",
         key="WebACLs", kwargs={"Scope": "REGIONAL"}),
    dict(service="acm", client="acm", method="list_certificates",
         key="CertificateSummaryList", paginate=True),
    dict(service="backup", client="backup", method="list_backup_vaults",
         key="BackupVaultList", paginate=True),
    dict(service="transfer", client="transfer", method="list_servers",
         key="Servers", paginate=True),
    dict(service="batch", client="batch",
         method="describe_compute_environments",
         key="computeEnvironments", paginate=True),
    dict(service="stepfunctions", client="stepfunctions",
         method="list_state_machines", key="stateMachines",
         paginate=True),
    dict(service="events", client="events", method="list_rules",
         key="Rules", paginate=True, label="EventBridge Rules"),
    dict(service="firehose", client="firehose",
         method="list_delivery_streams", key="DeliveryStreamNames"),
    dict(service="es", client="es",
         method="list_domain_names", key="DomainNames",
         label="OpenSearch/Elasticsearch Domains"),

    # --- Global (queried once regardless of --all-regions) ---
    dict(service="route53", client="route53",
         method="list_hosted_zones", key="HostedZones", global_svc=True,
         paginate=True),
    dict(service="cloudfront", client="cloudfront",
         method="list_distributions", key="DistributionList",
         nested_key="Items", global_svc=True),
    dict(service="ses", client="ses", method="list_identities",
         key="Identities", global_svc=True, paginate=True),
    dict(service="organizations", client="organizations",
         method="list_accounts", key="Accounts", global_svc=True,
         paginate=True),
]


def print_table(rows, headers):
    """
    Render a simple aligned text table (no external deps).
    rows: list of tuples, one per printed line.
    headers: tuple of column headers, same arity as rows.
    """
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(cells):
        return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))

    sep = "  ".join("-" * w for w in widths)
    print(f"{C.BOLD}{fmt_row(headers)}{C.END}")
    print(sep)
    for row in rows:
        print(fmt_row(row))


def get_regions(session, requested):
    """Resolve final region list based on user flags."""
    if requested:
        return requested
    try:
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
    except Exception:
        # No ec2:DescribeRegions permission (or no creds for that region yet)
        # -- fall back to the profile's configured/default region only.
        return [session.region_name or "us-east-1"]


def run_check(session, check, region):
    """Execute a single service check, return (status, count, items, err)."""
    client_name = check["client"]
    kwargs = dict(check.get("kwargs", {}))
    region_kw = {} if check.get("global_svc") else {"region_name": region}

    try:
        client = session.client(client_name, **region_kw)
    except Exception as e:
        return "error", 0, [], f"client init failed: {e}"

    try:
        method = getattr(client, check["method"])

        items = []
        if check.get("paginate") and client.can_paginate(check["method"]):
            paginator = client.get_paginator(check["method"])
            for page in paginator.paginate(**kwargs):
                page_items = page.get(check["key"], []) if check["key"] else [page]
                items.extend(page_items)
        else:
            resp = method(**kwargs)
            if check["key"] is None:
                items = [resp]
            else:
                items = resp.get(check["key"], [])

        # unwrap doubly-nested results (e.g. EC2 Reservations -> Instances)
        if check.get("nested_key"):
            flat = []
            for outer in items:
                if isinstance(outer, dict) and check["nested_key"] in outer:
                    flat.extend(outer[check["nested_key"]])
                else:
                    flat.append(outer)
            items = flat

        # normalize plain strings (e.g. dynamodb table names, ecs cluster arns)
        norm = []
        for it in items:
            if isinstance(it, str):
                norm.append({"Name": it})
            else:
                norm.append(it)

        return "accessible", len(norm), norm, None

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException",
                    "UnauthorizedOperation", "UnauthorizedException",
                    "AuthorizationError"):
            return "denied", 0, [], code
        if code in ("OptInRequired", "SubscriptionRequiredException",
                    "InvalidClientTokenId"):
            return "na", 0, [], code
        return "error", 0, [], f"{code}: {e.response.get('Error', {}).get('Message','')}"
    except (EndpointConnectionError,):
        return "na", 0, [], "service not available in this region"
    except BotoCoreError as e:
        return "error", 0, [], str(e)
    except Exception as e:
        return "error", 0, [], str(e)


def main():
    ap = argparse.ArgumentParser(
        description="Enumerate all AWS resources/services visible to a given AWS CLI profile.")
    ap.add_argument("--profile", help="AWS CLI profile name from ~/.aws/credentials + ~/.aws/config "
                                       "(supports static keys, session-token creds, assume-role, SSO)")
    ap.add_argument("--region", action="append",
                     help="Region to scan (repeatable). Default: profile's default region.")
    ap.add_argument("--all-regions", action="store_true",
                     help="Scan every enabled region (requires ec2:DescribeRegions, else falls back).")
    ap.add_argument("--services", help="Comma-separated list of service keys to limit the scan to "
                                        "(e.g. s3,iam,lambda,ec2). See --list-services.")
    ap.add_argument("--threads", type=int, default=12, help="Parallel worker threads (default: 12)")
    ap.add_argument("--full", action="store_true", help="Print every resource identifier, not just a preview.")
    ap.add_argument("--json", metavar="FILE", help="Also write full results as JSON to FILE.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    ap.add_argument("--quiet-denied", action="store_true", help="Hide the denied-services summary line.")
    ap.add_argument("--list-services", action="store_true",
                     help="List all service check keys this tool knows about, then exit.")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.off()

    if args.list_services:
        keys = sorted({c["service"] for c in SERVICE_CHECKS})
        print("\n".join(keys))
        return

    if not args.profile:
        ap.error("--profile is required (see --list-services for a dry run without it)")

    try:
        session = boto3.Session(profile_name=args.profile)
    except ProfileNotFound as e:
        sys.exit(f"[!] {e}\n    Check the profile name in ~/.aws/credentials and ~/.aws/config.")

    wanted = set(args.services.split(",")) if args.services else None
    checks = [c for c in SERVICE_CHECKS if not wanted or c["service"] in wanted]

    # --- Step 1: confirm identity first, fail fast with a clear message ---
    print(f"{C.B}{C.BOLD}[*] Resolving identity for profile '{args.profile}'...{C.END}")
    try:
        sts = session.client("sts", region_name=session.region_name or "us-east-1")
        ident = sts.get_caller_identity()
        print(f"{C.G}    Account : {ident['Account']}{C.END}")
        print(f"{C.G}    ARN     : {ident['Arn']}{C.END}")
        print(f"{C.G}    UserId  : {ident['UserId']}{C.END}\n")
    except NoCredentialsError:
        sys.exit(f"[!] No credentials found for profile '{args.profile}'. "
                  f"Check ~/.aws/credentials.")
    except ClientError as e:
        sys.exit(f"[!] sts:GetCallerIdentity failed -- credentials appear invalid/expired: {e}")

    regions = get_regions(session, args.region) if args.all_regions or args.region else \
        [session.region_name or "us-east-1"]
    print(f"{C.B}[*] Regions in scope: {', '.join(regions)}{C.END}")
    print(f"{C.B}[*] Running {len(checks)} service checks x {len(regions)} region(s)...{C.END}\n")

    jobs = []
    for check in checks:
        if check.get("global_svc"):
            jobs.append((check, None))
        else:
            for r in regions:
                jobs.append((check, r))

    results = []  # list of dicts
    lock = threading.Lock()

    def worker(check, region):
        status, count, items, err = run_check(session, check, region)
        return check, region, status, count, items, err

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(worker, c, r) for c, r in jobs]
        for fut in as_completed(futures):
            check, region, status, count, items, err = fut.result()
            results.append(dict(
                service=check["service"], label=check.get("label", check["method"]),
                method=check["method"], region=region, status=status,
                count=count, items=items, error=err,
            ))

    # --- Report ---
    accessible = [r for r in results if r["status"] == "accessible" and r["count"] > 0]
    empty_ok = [r for r in results if r["status"] == "accessible" and r["count"] == 0]
    denied = [r for r in results if r["status"] == "denied"]
    errored = [r for r in results if r["status"] == "error"]

    def region_tag(r):
        return f" [{r['region']}]" if r["region"] else " [global]"

    print(f"{C.BOLD}{C.G}=== ACCESSIBLE ({len(accessible)} checks returned data, "
          f"{sum(r['count'] for r in accessible)} resources total) ==={C.END}\n")

    # Build a flat SERVICE / ARN table. A service with N resources gets N
    # rows, one per ARN -- the service name repeats once per row, matching
    # how e.g. `s3` shows up twice if the profile can see two buckets.
    table_rows = []
    for r in sorted(accessible, key=lambda x: (x["service"], x["region"] or "")):
        preview = r["items"] if args.full else r["items"][:5]
        for it in preview:
            table_rows.append((r["service"], extract_identity(it)))
        if not args.full and r["count"] > 5:
            table_rows.append((r["service"], f"... +{r['count'] - 5} more (use --full to show all)"))

    print_table(table_rows, ("SERVICE", "ARN"))

    if empty_ok:
        print(f"\n{C.BOLD}{C.Y}=== ACCESSIBLE, NO RESOURCES FOUND ({len(empty_ok)}) ==={C.END}")
        for r in sorted(empty_ok, key=lambda x: (x["service"], x["region"] or "")):
            print(f"{C.Y}[ ] {r['service']:<15}{region_tag(r):<14} {r['label']}{C.END}")

    if not args.quiet_denied:
        print(f"\n{C.BOLD}{C.R}=== ACCESS DENIED ({len(denied)}) ==={C.END}")
        seen = set()
        for r in sorted(denied, key=lambda x: x["service"]):
            key = (r["service"], r["label"])
            if key in seen:
                continue
            seen.add(key)
            print(f"{C.R}[-] {r['service']:<15} {r['label']:<32} ({r['error']}){C.END}")

    if errored:
        print(f"\n{C.BOLD}{C.Y}=== ERRORS / NOT APPLICABLE ({len(errored)}) ==={C.END}")
        seen = set()
        for r in sorted(errored, key=lambda x: x["service"]):
            key = (r["service"], r["label"])
            if key in seen:
                continue
            seen.add(key)
            print(f"{C.Y}[?] {r['service']:<15} {r['label']:<32} {r['error']}{C.END}")

    print(f"\n{C.BOLD}Summary: {len(accessible)} with resources, {len(empty_ok)} accessible-but-empty, "
          f"{len(set((r['service'],r['label']) for r in denied))} denied, "
          f"{len(set((r['service'],r['label']) for r in errored))} errored/NA.{C.END}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "profile": args.profile,
                "identity": ident,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "regions": regions,
                "results": results,
            }, f, indent=2, default=str)
        print(f"\n{C.B}[*] Full JSON report written to {args.json}{C.END}")


if __name__ == "__main__":
    main()
