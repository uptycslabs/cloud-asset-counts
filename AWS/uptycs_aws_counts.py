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

ADAPTIVE_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"}, user_agent_extra="aws-resource-counter/1.1")


def get_boto3_session_from_creds(creds: Dict[str, str]) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def assume_role(sts, account_id: str, role_name: str, external_id: str = None, session_name: str = "aws-resource-count") -> Dict[str, str]:
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    params = {"RoleArn": role_arn, "RoleSessionName": session_name, "DurationSeconds": 3600}
    if external_id:
        params["ExternalId"] = external_id
    return sts.assume_role(**params)["Credentials"]


def list_org_accounts(mgmt_session: boto3.Session) -> List[Dict[str, str]]:
    org = mgmt_session.client("organizations", config=ADAPTIVE_CFG)
    accounts, token = [], None
    while True:
        kwargs = {"MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        resp = org.list_accounts(**kwargs)
        accounts.extend([{"Id": a["Id"], "Name": a.get("Name", "")} for a in resp.get("Accounts", []) if a["Status"] == "ACTIVE"])
        token = resp.get("NextToken")
        if not token:
            break
    return accounts


def get_all_regions(session: boto3.Session) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1", config=ADAPTIVE_CFG)
    return [r["RegionName"] for r in ec2.describe_regions(AllRegions=True)["Regions"] if r["OptInStatus"] in ("opt-in-not-required", "opted-in")]


def count_ec2(session, region):
    ec2 = session.client("ec2", region_name=region, config=ADAPTIVE_CFG)
    count, token = 0, None
    while True:
        kwargs = {"MaxResults": 1000}
        if token:
            kwargs["NextToken"] = token
        resp = ec2.describe_instances(**kwargs)
        for res in resp.get("Reservations", []):
            count += len(res.get("Instances", []))
        token = resp.get("NextToken")
        if not token:
            break
    return count


def count_lambda(session, region):
    lam = session.client("lambda", region_name=region, config=ADAPTIVE_CFG)
    total, token = 0, None
    while True:
        kwargs = {"MaxItems": 50}
        if token:
            kwargs["Marker"] = token
        resp = lam.list_functions(**kwargs)
        total += len(resp.get("Functions", []))
        token = resp.get("NextMarker")
        if not token:
            break
    return total


def count_s3(session):
    s3 = session.client("s3", config=ADAPTIVE_CFG)
    return len(s3.list_buckets().get("Buckets", []))


def count_iam(session):
    iam = session.client("iam", config=ADAPTIVE_CFG)
    users = roles = 0
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


def count_ecs(session, region):
    ecs = session.client("ecs", region_name=region, config=ADAPTIVE_CFG)
    clusters, token = [], None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = ecs.list_clusters(**kwargs)
        clusters.extend(resp.get("clusterArns", []))
        token = resp.get("nextToken")
        if not token:
            break

    ecs_services = ecs_ec2 = ecs_fargate = tasks_ec2 = tasks_fargate = 0

    for cluster in clusters:
        # --- Count services ---
        stoken = None
        while True:
            skw = {"cluster": cluster, "maxResults": 10}
            if stoken:
                skw["nextToken"] = stoken
            sresp = ecs.list_services(**skw)
            service_arns = sresp.get("serviceArns", [])
            if service_arns:
                desc = ecs.describe_services(cluster=cluster, services=service_arns)
                for s in desc.get("services", []):
                    ecs_services += 1
                    if s.get("launchType") == "FARGATE":
                        ecs_fargate += 1
                        tasks_fargate += s.get("runningCount", 0)
                    else:
                        ecs_ec2 += 1
                        tasks_ec2 += s.get("runningCount", 0)
            stoken = sresp.get("nextToken")
            if not stoken:
                break

        # --- Count standalone tasks not tied to a service ---
        ttoken = None
        while True:
            tkw = {"cluster": cluster, "maxResults": 100}
            if ttoken:
                tkw["nextToken"] = ttoken
            tresp = ecs.list_tasks(**tkw)
            task_arns = tresp.get("taskArns", [])
            if not task_arns:
                break
            tdesc = ecs.describe_tasks(cluster=cluster, tasks=task_arns)
            for t in tdesc.get("tasks", []):
                launch_type = t.get("launchType")
                # skip if this task belongs to a service (already counted)
                if t.get("group", "").startswith("service:"):
                    continue
                if launch_type == "FARGATE":
                    tasks_fargate += 1
                else:
                    tasks_ec2 += 1
            ttoken = tresp.get("nextToken")
            if not ttoken:
                break

    return len(clusters), ecs_services, ecs_ec2, ecs_fargate, tasks_ec2, tasks_fargate


def count_eks(session, region):
    eks = session.client("eks", region_name=region, config=ADAPTIVE_CFG)
    clusters, token = [], None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = eks.list_clusters(**kwargs)
        clusters.extend(resp.get("clusters", []))
        token = resp.get("nextToken")
        if not token:
            break

    total_ng = total_nodes = 0
    for c in clusters:
        ng_token = None
        while True:
            ng_kwargs = {"clusterName": c, "maxResults": 100}
            if ng_token:
                ng_kwargs["nextToken"] = ng_token
            ng_resp = eks.list_nodegroups(**ng_kwargs)
            nodegroups = ng_resp.get("nodegroups", [])
            total_ng += len(nodegroups)
            for ng in nodegroups:
                try:
                    desc = eks.describe_nodegroup(clusterName=c, nodegroupName=ng)
                    asgs = desc["nodegroup"]["resources"].get("autoScalingGroups", [])
                    asg_client = session.client("autoscaling", region_name=region, config=ADAPTIVE_CFG)
                    for asg in asgs:
                        ag = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg["name"]])
                        for g in ag.get("AutoScalingGroups", []):
                            total_nodes += len(g.get("Instances", []))
                except ClientError:
                    pass
            ng_token = ng_resp.get("nextToken")
            if not ng_token:
                break
    return len(clusters), total_ng, total_nodes


def count_for_account(base_session, account_id, account_name, regions, assume_role_name, external_id=None, use_current_session=False):
    sts = base_session.client("sts", config=ADAPTIVE_CFG)
    if use_current_session:
        sess = base_session
    else:
        try:
            creds = assume_role(sts, account_id, assume_role_name, external_id)
            sess = get_boto3_session_from_creds(creds)
        except ClientError as e:
            return {"account_id": account_id, "account_name": account_name, "error": f"AssumeRole failed: {e}"}

    try:
        s3_count = count_s3(sess)
    except ClientError:
        s3_count = -1
    try:
        iam_users, iam_roles = count_iam(sess)
    except ClientError:
        iam_users, iam_roles = -1, -1

    def region_worker(region):
        result = {
            "ec2": 0,
            "lambda": 0,
            "ecs_clusters": 0, "ecs_services": 0, "ecs_ec2": 0, "ecs_fargate": 0,
            "ecs_tasks_ec2": 0, "ecs_tasks_fargate": 0,
            "eks_clusters": 0, "eks_nodegroups": 0, "eks_nodes": 0
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
            c, s, e2, fg, te2, tfg = count_ecs(sess, region)
            result.update({"ecs_clusters": c, "ecs_services": s, "ecs_ec2": e2, "ecs_fargate": fg, "ecs_tasks_ec2": te2, "ecs_tasks_fargate": tfg})
        except ClientError:
            pass
        try:
            kc, ng, nd = count_eks(sess, region)
            result.update({"eks_clusters": kc, "eks_nodegroups": ng, "eks_nodes": nd})
        except ClientError:
            pass
        return result

    totals = {k: 0 for k in ["ec2", "lambda", "ecs_clusters", "ecs_services", "ecs_ec2", "ecs_fargate",
                             "ecs_tasks_ec2", "ecs_tasks_fargate", "eks_clusters", "eks_nodegroups", "eks_nodes"]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(regions))) as exe:
        for res in exe.map(region_worker, regions):
            for k, v in res.items():
                totals[k] += v

    totals.update({"s3_buckets": s3_count, "iam_users": iam_users, "iam_roles": iam_roles,
                   "account_id": account_id, "account_name": account_name})
    return totals


def main():
    parser = argparse.ArgumentParser(description="Count AWS resources (compute first, then others).", epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["org", "account"], required=True)
    parser.add_argument("--management-account-id")
    parser.add_argument("--account-id")
    parser.add_argument("--assume-role-name", default="OrganizationAccountAccessRole")
    parser.add_argument("--external-id")
    parser.add_argument("--regions", nargs="*")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--use-current-session", action="store_true")
    parser.add_argument("--profile")
    parser.add_argument("--log-file")

    args = parser.parse_args()
    base = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    caller = base.client("sts", config=ADAPTIVE_CFG).get_caller_identity().get("Account", "")

    targets = []
    if args.mode == "org":
        accts = list_org_accounts(base)
        targets = [(a["Id"], a["Name"]) for a in accts]
    else:
        targets = [(args.account_id, "")]

    regions = args.regions or get_all_regions(base)
    results = [count_for_account(base, aid, name, regions, args.assume_role_name, args.external_id, args.use_current_session or (caller == aid)) for aid, name in targets]

    totals = {k: sum(r.get(k, 0) for r in results if k in r) for k in results[0].keys() if k not in ("account_id", "account_name", "error")}

    if args.output == "json":
        print(json.dumps({"results": results, "totals": totals}, indent=2))
        return

    header = [
        ("Account ID", 14), ("Name", 20),
        ("EC2", 6), ("ECS-Tasks-Fargate", 20), ("Lambda", 8),
        ("EKS-Clusters", 13), ("EKS-NodeGroups", 15), ("EKS-Nodes", 11),
        ("ECS-Clusters", 14), ("ECS-Services", 14),
        ("ECS-Services-EC2", 17), ("ECS-Services-Fargate", 20),
        ("ECS-Tasks-EC2", 17),
        ("S3", 6), ("IAM Users", 11), ("IAM Roles", 11)
    ]
    widths = [w for _, w in header]
    def fmt(cols): return " ".join(str(c)[:w].ljust(w) for c, w in zip(cols, widths))
    print(fmt([h for h, _ in header]))
    print("-" * (sum(widths) + len(widths)))

    for r in results:
        print(fmt([
            r["account_id"], r["account_name"],
            r["ec2"], r["ecs_tasks_fargate"], r["lambda"],
            r["eks_clusters"], r["eks_nodegroups"], r["eks_nodes"],
            r["ecs_clusters"], r["ecs_services"],
            r["ecs_ec2"], r["ecs_fargate"], r["ecs_tasks_ec2"],
            r["s3_buckets"], r["iam_users"], r["iam_roles"]
        ]))

    print("\nTOTALS:")
    print(fmt([
        "Accounts", "",
        totals["ec2"], totals["ecs_tasks_fargate"], totals["lambda"],
        totals["eks_clusters"], totals["eks_nodegroups"], totals["eks_nodes"],
        totals["ecs_clusters"], totals["ecs_services"],
        totals["ecs_ec2"], totals["ecs_fargate"], totals["ecs_tasks_ec2"],
        totals["s3_buckets"], totals["iam_users"], totals["iam_roles"]
    ]))


if __name__ == "__main__":
    main()
