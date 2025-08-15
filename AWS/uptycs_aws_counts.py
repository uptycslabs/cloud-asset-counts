#!/usr/bin/env python3
EXAMPLES = """\
Examples:

  Single account using current profile
    python3 uptycs_aws_counts.py --mode account --account-id 123456789012 --use-current-session --output json

  Org-wide from management (uses AWS_PROFILE or --profile)
    python3 uptycs_aws_counts.py --mode org --management-account-id 123456789012 --assume-role-name OrganizationAccountAccessRole --output table

  Org-wide with a named profile
    python3 uptycs_aws_counts.py --mode org --management-account-id 123456789012 --assume-role-name OrganizationAccountAccessRole --profile mgmt --output json

  Limit regions and log to file
    python3 uptycs_aws_counts.py --mode account --account-id 123456789012 --regions us-east-1 us-west-2 --output csv --log-file out.jsonl
"""

import argparse
import concurrent.futures
import csv
import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ADAPTIVE_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"}, user_agent_extra="aws-resource-counter/1.0")

def get_boto3_session_from_creds(creds: Dict[str, str]) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def assume_role(sts, account_id: str, role_name: str, external_id: str = None, session_name: str = "aws-resource-count") -> Dict[str, str]:
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    params = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": 3600,
    }
    if external_id:
        params["ExternalId"] = external_id
    resp = sts.assume_role(**params)
    return resp["Credentials"]


def list_org_accounts(mgmt_session: boto3.Session) -> List[Dict[str, str]]:
    org = mgmt_session.client("organizations", config=ADAPTIVE_CFG)
    accounts = []
    token = None
    while True:
        kwargs = {"MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        resp = org.list_accounts(**kwargs)
        for a in resp.get("Accounts", []):
            if a.get("Status") == "ACTIVE":
                accounts.append({"Id": a["Id"], "Name": a.get("Name", "")})
        token = resp.get("NextToken")
        if not token:
            break
    return accounts


def get_all_regions(base_session: boto3.Session) -> List[str]:
    ec2 = base_session.client("ec2", region_name="us-east-1", config=ADAPTIVE_CFG)
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [r["RegionName"] for r in regions if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")]

def count_ec2(session: boto3.Session, region: str) -> int:
    ec2 = session.client("ec2", region_name=region, config=ADAPTIVE_CFG)
    count = 0
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["NextToken"] = token
        resp = ec2.describe_instances(**kwargs)
        for res in resp.get("Reservations", []):
            count += len(res.get("Instances", []))
        token = resp.get("NextToken")
        if not token:
            break
    return count


def count_lambda(session: boto3.Session, region: str) -> int:
    lam = session.client("lambda", region_name=region, config=ADAPTIVE_CFG)
    count = 0
    token = None
    while True:
        kwargs = {"MaxItems": 50}
        if token:
            kwargs["Marker"] = token
        resp = lam.list_functions(**kwargs)
        count += len(resp.get("Functions", []))
        token = resp.get("NextMarker")
        if not token:
            break
    return count


def count_ecs(session: boto3.Session, region: str) -> Tuple[int, int]:
    ecs = session.client("ecs", region_name=region, config=ADAPTIVE_CFG)
    # clusters
    clusters = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = ecs.list_clusters(**kwargs)
        clusters.extend(resp.get("clusterArns", []))
        token = resp.get("nextToken")
        if not token:
            break
    total_services = 0
    for arn in clusters:
        stoken = None
        while True:
            skw = {"cluster": arn, "maxResults": 10}
            if stoken:
                skw["nextToken"] = stoken
            sresp = ecs.list_services(**skw)
            total_services += len(sresp.get("serviceArns", []))
            stoken = sresp.get("nextToken")
            if not stoken:
                break
    return len(clusters), total_services


def count_s3(session: boto3.Session) -> int:
    s3 = session.client("s3", config=ADAPTIVE_CFG)
    resp = s3.list_buckets()
    return len(resp.get("Buckets", []))


def count_iam(session: boto3.Session) -> Tuple[int, int]:
    iam = session.client("iam", config=ADAPTIVE_CFG)
    users = 0
    token = None
    while True:
        kwargs = {"MaxItems": 1000}
        if token:
            kwargs["Marker"] = token
        resp = iam.list_users(**kwargs)
        users += len(resp.get("Users", []))
        token = resp.get("Marker") if resp.get("IsTruncated") else None
        if not token:
            break
    roles = 0
    token = None
    while True:
        kwargs = {"MaxItems": 1000}
        if token:
            kwargs["Marker"] = token
        resp = iam.list_roles(**kwargs)
        roles += len(resp.get("Roles", []))
        token = resp.get("Marker") if resp.get("IsTruncated") else None
        if not token:
            break
    return users, roles


# NEW: EKS counts (clusters + nodegroups)
def count_eks(session: boto3.Session, region: str) -> Tuple[int, int]:
    eks = session.client("eks", region_name=region, config=ADAPTIVE_CFG)
    clusters: List[str] = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = eks.list_clusters(**kwargs)
        clusters.extend(resp.get("clusters", []))
        token = resp.get("nextToken")
        if not token:
            break

    total_ng = 0
    for name in clusters:
        ng_token = None
        while True:
            ng_kwargs = {"clusterName": name, "maxResults": 100}
            if ng_token:
                ng_kwargs["nextToken"] = ng_token
            ng_resp = eks.list_nodegroups(**ng_kwargs)
            total_ng += len(ng_resp.get("nodegroups", []))
            ng_token = ng_resp.get("nextToken")
            if not ng_token:
                break
    return len(clusters), total_ng


def count_for_account(base_session: boto3.Session, account_id: str, account_name: str, regions: List[str], assume_role_name: str, external_id: str = None, use_current_session: bool = False) -> Dict[str, int]:
    sts = base_session.client("sts", config=ADAPTIVE_CFG)
    sess: boto3.Session
    if use_current_session:
        sess = base_session
    else:
        try:
            creds = assume_role(sts, account_id, assume_role_name, external_id)
        except ClientError as e:
            return {
                "account_id": account_id,
                "account_name": account_name,
                "error": f"AssumeRole failed: {e.response['Error'].get('Message', str(e))}",
            }
        sess = get_boto3_session_from_creds(creds)

    try:
        s3_count = count_s3(sess)
    except ClientError as e:
        s3_count = -1
    try:
        iam_users, iam_roles = count_iam(sess)
    except ClientError as e:
        iam_users, iam_roles = -1, -1

    def regional_worker(region: str) -> Tuple[str, Dict[str, int]]:
        result = {
            "ec2": 0,
            "lambda": 0,
            "ecs_clusters": 0,
            "ecs_services": 0,
            "eks_clusters": 0,       # NEW
            "eks_nodegroups": 0      # NEW
        }
        try:
            result["ec2"] = count_ec2(sess, region)
        except ClientError:
            pass
        try:
            result["lambda"] = count_lambda(sess, region)
        except ClientError:
            pass
        try:
            c, s = count_ecs(sess, region)
            result["ecs_clusters"], result["ecs_services"] = c, s
        except ClientError:
            pass
        try:
            kc, ng = count_eks(sess, region)   # NEW
            result["eks_clusters"], result["eks_nodegroups"] = kc, ng
        except ClientError:
            pass
        return region, result

    regional_totals = {
        "ec2": 0,
        "lambda": 0,
        "ecs_clusters": 0,
        "ecs_services": 0,
        "eks_clusters": 0,      # NEW
        "eks_nodegroups": 0     # NEW
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(regions) or 1)) as exe:
        for _, res in exe.map(regional_worker, regions):
            for k, v in res.items():
                regional_totals[k] += v

    output = {
        "account_id": account_id,
        "account_name": account_name,
        "ec2": regional_totals["ec2"],
        "lambda": regional_totals["lambda"],
        "s3_buckets": s3_count,
        "iam_users": iam_users,
        "iam_roles": iam_roles,
        "ecs_clusters": regional_totals["ecs_clusters"],
        "ecs_services": regional_totals["ecs_services"],
        "eks_clusters": regional_totals["eks_clusters"],        # NEW
        "eks_nodegroups": regional_totals["eks_nodegroups"],    # NEW
    }
    return output


def main():
    parser = argparse.ArgumentParser(description="Count AWS resources in one or many accounts.", epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["org", "account"], required=True, help="'org' to enumerate all ACTIVE accounts in the organization, 'account' for a single account")
    parser.add_argument("--management-account-id", help="Management (payer) account ID (required for --mode org)")
    parser.add_argument("--account-id", help="Child account ID (required for --mode account)")
    parser.add_argument("--assume-role-name", default="OrganizationAccountAccessRole", help="Role name to assume in target accounts (ignored when --use-current-session applies)")
    parser.add_argument("--external-id", default=None, help="External ID required by the assume role (optional)")
    parser.add_argument("--regions", nargs="*", default=None, help="Specific regions to scan (default: all enabled regions)")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("--use-current-session", action="store_true", help="Use current AWS credentials for the target account (skip STS AssumeRole). If --mode account and the caller account matches --account-id, this is implied.")
    parser.add_argument("--profile", default=None, help="AWS profile to use (overrides AWS_PROFILE env var)")
    parser.add_argument("--log-file", default=None, help="If set, append a JSON log line with results to this file (JSONL format)")

    args = parser.parse_args()

    base_session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    caller_acct = None
    try:
        caller_acct = base_session.client("sts", config=ADAPTIVE_CFG).get_caller_identity()["Account"]
    except Exception:
        pass

    targets: List[Tuple[str, str]] = []

    if args.mode == "org":
        if not args.management_account_id:
            print("--management-account-id is required when --mode org", file=sys.stderr)
            sys.exit(2)
        accounts = list_org_accounts(base_session)
        if not accounts:
            print("No ACTIVE accounts found in the organization.")
            sys.exit(0)
        targets = [(a["Id"], a.get("Name", "")) for a in accounts]
    else:
        if not args.account_id:
            print("--account-id is required when --mode account", file=sys.stderr)
            sys.exit(2)
        targets = [(args.account_id, "")]

    regions = args.regions or get_all_regions(base_session)
    if not regions:
        print("No enabled regions discovered.", file=sys.stderr)
        sys.exit(2)

    results: List[Dict[str, int]] = []

    for acct_id, acct_name in targets:
        summary = count_for_account(
            base_session,
            account_id=acct_id,
            account_name=acct_name,
            regions=regions,
            assume_role_name=args.assume_role_name,
            external_id=args.external_id,
            use_current_session=(args.use_current_session or (caller_acct == acct_id)),
        )
        results.append(summary)

    totals = {
        "accounts": len(results),
        "ec2": sum(r.get("ec2", 0) for r in results if "ec2" in r),
        "lambda": sum(r.get("lambda", 0) for r in results if "lambda" in r),
        "s3_buckets": sum(r.get("s3_buckets", 0) for r in results if "s3_buckets" in r),
        "iam_users": sum(r.get("iam_users", 0) for r in results if "iam_users" in r),
        "iam_roles": sum(r.get("iam_roles", 0) for r in results if "iam_roles" in r),
        "ecs_clusters": sum(r.get("ecs_clusters", 0) for r in results if "ecs_clusters" in r),
        "ecs_services": sum(r.get("ecs_services", 0) for r in results if "ecs_services" in r),
        "eks_clusters": sum(r.get("eks_clusters", 0) for r in results if "eks_clusters" in r),           # NEW
        "eks_nodegroups": sum(r.get("eks_nodegroups", 0) for r in results if "eks_nodegroups" in r),     # NEW
    }

    if args.log_file:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "mode": args.mode,
            "management_account_id": args.management_account_id,
            "account_id": args.account_id,
            "profile": args.profile,
            "regions": regions,
            "results": results,
            "totals": totals,
        }
        try:
            with open(args.log_file, "a", encoding="utf-8") as lf:
                lf.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"[warn] failed to write log file {args.log_file}: {e}", file=sys.stderr)

    if args.output == "json":
        print(json.dumps({"results": results, "totals": totals}, indent=2))
        return

    if args.output == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow([
            "account_id", "account_name",
            "ec2", "lambda", "s3_buckets", "iam_users", "iam_roles",
            "ecs_clusters", "ecs_services",
            "eks_clusters", "eks_nodegroups"   # NEW
        ])
        for r in results:
            writer.writerow([
                r.get("account_id"),
                r.get("account_name", ""),
                r.get("ec2", r.get("error", "")),
                r.get("lambda", ""),
                r.get("s3_buckets", ""),
                r.get("iam_users", ""),
                r.get("iam_roles", ""),
                r.get("ecs_clusters", ""),
                r.get("ecs_services", ""),
                r.get("eks_clusters", ""),
                r.get("eks_nodegroups", ""),
            ])
        writer.writerow([
            "TOTAL", "",
            totals["ec2"], totals["lambda"], totals["s3_buckets"], totals["iam_users"], totals["iam_roles"],
            totals["ecs_clusters"], totals["ecs_services"],
            totals["eks_clusters"], totals["eks_nodegroups"]
        ])
        return

    header = [
        ("Account ID", 14), ("Name", 24),
        ("EC2", 7), ("Lambda", 8), ("S3", 6),
        ("IAM Users", 11), ("IAM Roles", 11),
        ("ECS Clusters", 13), ("ECS Services", 13),
        ("EKS Clusters", 13), ("EKS NodeGrps", 13)  # NEW
    ]
    def fmt_row(cols, widths):
        return " ".join(str(c)[:w].ljust(w) for (c, w) in zip(cols, widths))
    widths = [w for _, w in header]
    print(fmt_row([h for h, _ in header], widths))
    print("-" * (sum(widths) + len(widths) - 1))
    for r in results:
        if "error" in r:
            # merge all numeric columns into one wide error cell, keep trailing blanks for remaining columns
            merged_width = sum(widths[2:]) + len(widths[2:]) - 1
            print(fmt_row(
                [r.get("account_id"), r.get("account_name", ""), r["error"]] + [""] * (len(widths) - 3),
                [14, 24, merged_width] + [0] * (len(widths) - 3)
            ))
            continue
        print(fmt_row([
            r.get("account_id"), r.get("account_name", ""),
            r.get("ec2", 0), r.get("lambda", 0), r.get("s3_buckets", 0),
            r.get("iam_users", 0), r.get("iam_roles", 0),
            r.get("ecs_clusters", 0), r.get("ecs_services", 0),
            r.get("eks_clusters", 0), r.get("eks_nodegroups", 0)
        ], widths))
    print("\nTOTALS:")
    print(fmt_row([
        "Accounts", "",
        totals["ec2"], totals["lambda"], totals["s3_buckets"],
        totals["iam_users"], totals["iam_roles"],
        totals["ecs_clusters"], totals["ecs_services"],
        totals["eks_clusters"], totals["eks_nodegroups"]
    ], widths))


if __name__ == "__main__":
    main()