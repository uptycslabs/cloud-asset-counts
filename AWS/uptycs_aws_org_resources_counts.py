#!/usr/bin/env python3
import boto3
import csv
import sys
from datetime import datetime
from botocore.config import Config
from botocore.exceptions import ClientError

# ==============================
# Config & Constants
# ==============================
BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "standard"},
    read_timeout=60,
    connect_timeout=10,
    user_agent_extra="uptycs-aws-compute-counter/1.0"
)

OUTPUT_FILENAME_TEMPLATE = "uptycs_aws_compute_counts_{org_id}_{date}.csv"
HEADER = [
    "account", "region",
    "ec2_instances",
    "lambda_functions",
    "ecs_clusters",
    "ecs_services_active",
    "ecs_tasks_running",
    "eks_clusters",
    "eks_nodegroups"
]

# ==============================
# STS / Orgs helpers
# ==============================
def assume_role(profile_name, account_id, role_name):
    """Assume a cross-account role in the given member account."""
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client("sts", config=BOTO_CONFIG)
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="UptycsComputeCounter"
        )
        creds = assumed_role["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    except ClientError as e:
        print(f"[WARN] AssumeRole failed for {account_id}: {e}")
        return None

def get_org_id(profile_name):
    """Get the AWS Organization ID using the provided profile (must have orgs perms)."""
    try:
        session = boto3.Session(profile_name=profile_name)
        org_client = session.client("organizations", config=BOTO_CONFIG)
        response = org_client.describe_organization()
        return response["Organization"]["Id"]
    except ClientError as e:
        print(f"[ERROR] Retrieving organization ID failed: {e}")
        sys.exit(1)

def list_org_accounts(profile_name):
    """List all accounts in the org with pagination."""
    session = boto3.Session(profile_name=profile_name)
    org_client = session.client("organizations", config=BOTO_CONFIG)
    try:
        accounts = []
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            accounts.extend(page.get("Accounts", []))
        return accounts
    except ClientError as e:
        print(f"[ERROR] Listing accounts failed: {e}")
        sys.exit(1)

# ==============================
# Region helpers
# ==============================
def get_enabled_regions(session):
    """
    Return only enabled/opted-in regions for the account.
    This avoids errors from calling services in disabled regions.
    """
    ec2 = session.client("ec2", region_name="us-east-1", config=BOTO_CONFIG)
    try:
        regions = ec2.describe_regions(AllRegions=True)["Regions"]
        enabled = [
            r["RegionName"]
            for r in regions
            if r.get("OptInStatus") in (None, "opt-in-not-required", "opted-in")
        ]
        return enabled
    except ClientError as e:
        print(f"[WARN] describe_regions failed: {e}")
        return []

# ==============================
# Counters (Compute only)
# ==============================
def count_ec2_instances(session, region):
    """Count EC2 instances in non-terminated states."""
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    count = 0
    paginator = ec2.get_paginator("describe_instances")
    filters = [{"Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped"]}]
    for page in paginator.paginate(Filters=filters):
        for r in page.get("Reservations", []):
            count += len(r.get("Instances", []))
    return count

def count_lambda_functions(session, region):
    """Count Lambda functions (regional)."""
    lam = session.client("lambda", region_name=region, config=BOTO_CONFIG)
    count = 0
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        count += len(page.get("Functions", []))
    return count

def count_ecs_clusters(session, region):
    """Count ECS clusters (regional)."""
    ecs = session.client("ecs", region_name=region, config=BOTO_CONFIG)
    count = 0
    paginator = ecs.get_paginator("list_clusters")
    for page in paginator.paginate():
        count += len(page.get("clusterArns", []))
    return count

def count_ecs_services_active(session, region):
    """Count ACTIVE ECS services across all clusters in a region."""
    ecs = session.client("ecs", region_name=region, config=BOTO_CONFIG)
    clusters = []
    for page in ecs.get_paginator("list_clusters").paginate():
        clusters.extend(page.get("clusterArns", []))

    total = 0
    for cluster in clusters:
        paginator = ecs.get_paginator("list_services")
        for page in paginator.paginate(cluster=cluster, status="ACTIVE"):
            total += len(page.get("serviceArns", []))
    return total

def count_ecs_tasks_running(session, region):
    """Count RUNNING ECS tasks across all clusters in a region (actual compute usage)."""
    ecs = session.client("ecs", region_name=region, config=BOTO_CONFIG)
    clusters = []
    for page in ecs.get_paginator("list_clusters").paginate():
        clusters.extend(page.get("clusterArns", []))

    total = 0
    for cluster in clusters:
        paginator = ecs.get_paginator("list_tasks")
        for page in paginator.paginate(cluster=cluster, desiredStatus="RUNNING"):
            total += len(page.get("taskArns", []))
    return total

def count_eks_clusters(session, region):
    """Count EKS clusters (control plane)."""
    eks = session.client("eks", region_name=region, config=BOTO_CONFIG)
    total = 0
    paginator = eks.get_paginator("list_clusters")
    for page in paginator.paginate():
        total += len(page.get("clusters", []))
    return total

def count_eks_nodegroups(session, region):
    """Count EKS managed nodegroups across all clusters in a region."""
    eks = session.client("eks", region_name=region, config=BOTO_CONFIG)
    clusters = []
    for page in eks.get_paginator("list_clusters").paginate():
        clusters.extend(page.get("clusters", []))

    total = 0
    for c in clusters:
        paginator = eks.get_paginator("list_nodegroups")
        for page in paginator.paginate(clusterName=c):
            total += len(page.get("nodegroups", []))
    return total

# ==============================
# Per-region wrapper
# ==============================
def count_resources_in_region(session, region):
    ec2_i = lam = ecs_c = ecs_s = ecs_t = eks_c = eks_ng = 0
    try:
        ec2_i = count_ec2_instances(session, region)
    except ClientError as e:
        print(f"[WARN] EC2 {region}: {e}")

    try:
        lam = count_lambda_functions(session, region)
    except ClientError as e:
        print(f"[WARN] Lambda {region}: {e}")

    try:
        ecs_c = count_ecs_clusters(session, region)
    except ClientError as e:
        print(f"[WARN] ECS clusters {region}: {e}")

    try:
        ecs_s = count_ecs_services_active(session, region)
    except ClientError as e:
        print(f"[WARN] ECS services {region}: {e}")

    try:
        ecs_t = count_ecs_tasks_running(session, region)
    except ClientError as e:
        print(f"[WARN] ECS tasks {region}: {e}")

    try:
        eks_c = count_eks_clusters(session, region)
    except ClientError as e:
        print(f"[WARN] EKS clusters {region}: {e}")

    try:
        eks_ng = count_eks_nodegroups(session, region)
    except ClientError as e:
        print(f"[WARN] EKS nodegroups {region}: {e}")

    return ec2_i, lam, ecs_c, ecs_s, ecs_t, eks_c, eks_ng

# ==============================
# Main
# ==============================
def main(profile_name, role_name):
    org_id = get_org_id(profile_name)
    the_date = datetime.now().strftime("%Y-%m-%d")
    output_file = OUTPUT_FILENAME_TEMPLATE.format(org_id=org_id, date=the_date)

    accounts = list_org_accounts(profile_name)
    total_accounts = len(accounts)

    totals = {
        "ec2": 0,
        "lambda": 0,
        "ecs_clusters": 0,
        "ecs_services": 0,
        "ecs_tasks": 0,
        "eks_clusters": 0,
        "eks_nodegroups": 0
    }

    with open(output_file, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(HEADER)

        for acct in accounts:
            account_id = acct["Id"]
            member_sess = assume_role(profile_name, account_id, role_name)
            if not member_sess:
                continue

            regions = get_enabled_regions(member_sess)

            for region in regions:
                ec2_i, lam, ecs_c, ecs_s, ecs_t, eks_c, eks_ng = count_resources_in_region(member_sess, region)

                # Only write non-empty rows to keep the CSV tidy
                if any([ec2_i, lam, ecs_c, ecs_s, ecs_t, eks_c, eks_ng]):
                    writer.writerow([account_id, region, ec2_i, lam, ecs_c, ecs_s, ecs_t, eks_c, eks_ng])

                # Accumulate totals
                totals["ec2"] += ec2_i
                totals["lambda"] += lam
                totals["ecs_clusters"] += ecs_c
                totals["ecs_services"] += ecs_s
                totals["ecs_tasks"] += ecs_t
                totals["eks_clusters"] += eks_c
                totals["eks_nodegroups"] += eks_ng

        # Totals row (single summary line)
        writer.writerow([
            "TOTAL", "ALL",
            totals["ec2"],
            totals["lambda"],
            totals["ecs_clusters"],
            totals["ecs_services"],
            totals["ecs_tasks"],
            totals["eks_clusters"],
            totals["eks_nodegroups"],
        ])

        # Metadata line
        writer.writerow([])
        writer.writerow([f"Total number of accounts in Organization {org_id}", total_accounts])

    print(f"[OK] Compute resource counts written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <aws_profile_name> <cross_account_role_name>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
