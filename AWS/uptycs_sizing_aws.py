#!/usr/bin/env python3

""" 
Please refer README.md for more information on how to use the script

Version: 1.2.0
"""

import argparse
import concurrent.futures
import csv
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ParamValidationError

ADAPTIVE_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"}, user_agent_extra="aws-resource-counter/1.1")

# The single source of field order for every output format (table, csv, json),
# so their columns can never diverge. Each entry is (label, json key, table width).
OUTPUT_FIELDS = [
    ("EC2-Standalone", "ec2_standalone", 15),
    ("ECS-Clusters", "ecs_clusters", 14),
    ("ECS-Services-Total", "ecs_services_total", 19),
    ("ECS-Services-EC2", "ecs_services_ec2", 17),
    ("ECS-Services-Fargate", "ecs_services_fargate", 21),
    ("ECS-Tasks-EC2", "ecs_tasks_ec2", 14),
    ("ECS-Tasks-Fargate", "ecs_tasks_fargate", 18),
    ("ECS-Container-Instances", "ecs_container_instances", 24),
    ("EKS-Clusters", "eks_clusters", 13),
    ("EKS-NodeGroups", "eks_nodegroups", 15),
    ("EKS-Nodes", "eks_nodes", 11),
    ("Lambda-Functions", "lambda_functions", 17),
    ("S3-Buckets", "s3_buckets", 11),
    ("IAM-Users", "iam_users", 11),
    ("IAM-Roles", "iam_roles", 11),
]

# The per-region and account-wide count fields reported for each account, kept
# in OUTPUT_FIELDS order so result dicts are built in canonical order and every
# format (including JSON, which serializes dict insertion order) stays in sync
# without any per-record reordering.
REGIONAL_FIELDS = ("ec2_standalone", "ecs_clusters", "ecs_services_total", "ecs_services_ec2",
                   "ecs_services_fargate", "ecs_tasks_ec2", "ecs_tasks_fargate",
                   "ecs_container_instances", "eks_clusters", "eks_nodegroups", "eks_nodes",
                   "lambda_functions")
GLOBAL_FIELDS = ("s3_buckets", "iam_users", "iam_roles")


def get_boto3_session_from_creds(creds: Dict[str, str]) -> boto3.Session:
    """Build an AWS session from a set of temporary credentials.

    Used after assuming a role in another account, so the following API calls
    run as that account.
    """
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def assume_role(sts, account_id: str, role_name: str, external_id: str = None, session_name: str = "aws-resource-count") -> Dict[str, str]:
    """Assume a role in a target account and hand back temporary credentials.

    This is how the script reaches into another account to count its resources.
    The credentials last one hour, which is plenty for a single scan. Some roles
    require an external ID before they can be assumed; pass it when yours does.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    params = {"RoleArn": role_arn, "RoleSessionName": session_name, "DurationSeconds": 3600}
    if external_id:
        params["ExternalId"] = external_id
    return sts.assume_role(**params)["Credentials"]


def list_org_accounts(mgmt_session: boto3.Session) -> List[Dict[str, str]]:
    """List every active account in the AWS organization.

    These are the accounts an org-wide scan will cover. Suspended or closed
    accounts are left out, since there is nothing to count in them.
    """
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
    """List the regions this account can actually use.

    These are the regions the scan will look in. Regions the account has not
    turned on are left out, so counting never fails trying to reach a region
    that isn't available.
    """
    ec2 = session.client("ec2", region_name="us-east-1", config=ADAPTIVE_CFG)
    return [r["RegionName"] for r in ec2.describe_regions(AllRegions=True)["Regions"] if r["OptInStatus"] in ("opt-in-not-required", "opted-in")]


def count_ec2(session, region):
    """Count the EC2 instances in a region.

    Counts every instance that currently exists -- running, or stopped but not
    deleted. Terminated instances are not counted, even though AWS keeps listing
    them for about an hour after they are shut down.

    Along with the count it reports which instances were counted, so that an
    instance that is also an ECS container host or an EKS worker node is only
    counted once.
    """
    ec2 = session.client("ec2", region_name=region, config=ADAPTIVE_CFG)
    instance_ids = set()
    token = None

    while True:
        kwargs = {
            "MaxResults": 1000,
            "Filters": [{
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped"],
            }],
        }
        if token:
            kwargs["NextToken"] = token
        resp = ec2.describe_instances(**kwargs)
        for reservation in resp.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_ids.add(instance["InstanceId"])

        token = resp.get("NextToken")
        if not token:
            break

    return len(instance_ids), instance_ids


def count_lambda(session, region):
    """Count the Lambda (serverless) functions in a region."""
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
    """Count the S3 storage buckets in the account.

    Buckets aren't tied to a single region, so they're counted once for the
    whole account rather than region by region.
    """
    s3 = session.client("s3", config=ADAPTIVE_CFG)
    return len(s3.list_buckets().get("Buckets", []))


def count_iam(session):
    """Count the IAM users and roles in the account.

    Users and roles aren't tied to a single region, so they're counted once for
    the whole account rather than region by region.
    """
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


def get_account_alias(session):
    """Return the account's IAM alias, or "" if none is set.

    In account mode there's no Organizations name to use, so the IAM account
    alias -- the friendly name in the sign-in URL -- serves as the account name.
    An account can have at most one alias, and may have none.
    """
    try:
        iam = session.client("iam", config=ADAPTIVE_CFG)
        return (iam.list_account_aliases().get("AccountAliases") or [""])[0]
    except ClientError:
        return ""


def resolve_external_ec2_hosts(session, region, host_ids):
    """Identify ECS Anywhere hosts that are actually EC2 instances.

    ECS Anywhere lets machines from anywhere -- on-premises, another cloud, or an
    ordinary EC2 instance -- register to run ECS tasks. Each one registers under
    its own ECS Anywhere ID rather than an EC2 ID, so an EC2 instance registered
    this way looks like a separate machine and would otherwise be counted both as
    an EC2 instance and as a container host.

    This matches each such host by its IP address to a running EC2 instance and,
    on a match, counts it under its EC2 identity so the machine is counted only
    once. Hosts that are genuinely outside AWS find no match and are counted as
    separate container hosts.
    """
    external = {h for h in host_ids if h.startswith("mi-")}
    if not external:
        return host_ids
    ssm = session.client("ssm", region_name=region, config=ADAPTIVE_CFG)
    ec2 = session.client("ec2", region_name=region, config=ADAPTIVE_CFG)
    resolved = set(host_ids) - external
    warned = False
    for mid in external:
        real = mid
        try:
            info = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [mid]}]).get("InstanceInformationList", [])
            ip = info[0].get("IPAddress") if info else None
            if ip:
                r = ec2.describe_instances(Filters=[
                    {"Name": "private-ip-address", "Values": [ip]},
                    {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
                for res in r.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        real = inst["InstanceId"]
                        break
        except ClientError as e:
            if not warned:
                print(f"WARNING: {region}: could not reconcile ECS Anywhere hosts with EC2 "
                      f"(some may be double-counted as both EC2 and container hosts): {e}",
                      file=sys.stderr)
                warned = True
        resolved.add(real)
    return resolved


def capacity_provider_kinds(ecs):
    """Work out whether each capacity provider runs on Fargate or EC2.

    A capacity provider is the rule that decides where a service's tasks run.
    The two built-in ones, FARGATE and FARGATE_SPOT, are serverless (Fargate).
    A capacity provider backed by an Auto Scaling group or by ECS Managed
    Instances runs on your own EC2 instances. Returns a lookup from provider
    name to "fargate" or "ec2" so services and tasks are counted against the
    kind of compute they actually use.
    """
    kinds = {"FARGATE": "fargate", "FARGATE_SPOT": "fargate"}
    token = None
    while True:
        kwargs = {"maxResults": 100, **({"nextToken": token} if token else {})}
        resp = ecs.describe_capacity_providers(**kwargs)
        for cp in resp.get("capacityProviders", []):
            ec2_backed = cp.get("autoScalingGroupProvider") or cp.get("managedInstancesProvider")
            kinds[cp.get("name", "")] = "ec2" if ec2_backed else "fargate"
        token = resp.get("nextToken")
        if not token:
            break
    return kinds


def count_ecs(session, region):
    """Count ECS usage in a region, split into EC2-backed and Fargate.

    Across every ECS cluster in the region this counts:

    * **Clusters.**
    * **Services**, split by where they run: Fargate (serverless) or EC2
      (your own instances).
    * **Running tasks**, also split Fargate vs EC2, covering both the tasks that
      belong to a service and standalone tasks started on their own; each task is
      counted once.
    * **Container hosts** -- the active, reachable machines registered to run
      ECS tasks on EC2.

    A machine registered as a container host is often also an EC2 instance.
    Those that are get matched back to their EC2 identity so the same machine is
    counted once, not once as an EC2 instance and again as a container host.
    Container hosts that are not EC2 instances (ECS Anywhere) are counted on
    their own.
    """
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

    # Resolve capacity-provider names to Fargate vs EC2 once for the region.
    cp_kinds = capacity_provider_kinds(ecs)

    ecs_services = ecs_ec2 = ecs_fargate = tasks_ec2 = tasks_fargate = 0
    container_instance_ids = set()

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
                    # A service either states its compute directly or points to
                    # a capacity provider we look up to find where it runs.
                    if s.get("launchType"):
                        is_fargate = s["launchType"] == "FARGATE"
                    else:
                        kinds = [cp_kinds.get(c.get("capacityProvider"))
                                 for c in s.get("capacityProviderStrategy") or []]
                        is_fargate = "ec2" not in kinds
                    if is_fargate:
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
                # skip if this task belongs to a service (already counted)
                if t.get("group", "").startswith("service:"):
                    continue
 
                launch_type = t.get("launchType")
                cap = t.get("capacityProviderName", "")
                if launch_type == "FARGATE" or cp_kinds.get(cap) == "fargate":
                    tasks_fargate += 1
                else:
                    tasks_ec2 += 1
            ttoken = tresp.get("nextToken")
            if not ttoken:
                break

        # --- Collect the machines registered to run ECS tasks on EC2 ---
        citoken = None
        while True:
            ckw = {"cluster": cluster, "maxResults": 100}
            if citoken:
                ckw["nextToken"] = citoken
            cresp = ecs.list_container_instances(**ckw)
            ci_arns = cresp.get("containerInstanceArns", [])
            if ci_arns:
                cdesc = ecs.describe_container_instances(cluster=cluster, containerInstances=ci_arns)
                for ci in cdesc.get("containerInstances", []):
                    eid = ci.get("ec2InstanceId", "")
                    if eid and ci.get("status") in ("ACTIVE", "DRAINING") and ci.get("agentConnected"):
                        container_instance_ids.add(eid)
            citoken = cresp.get("nextToken")
            if not citoken:
                break

    container_instance_ids = resolve_external_ec2_hosts(session, region, container_instance_ids)
    return len(clusters), ecs_services, ecs_ec2, ecs_fargate, tasks_ec2, tasks_fargate, container_instance_ids


# Tags that EKS puts on every worker node it manages; used to pick EKS worker
# nodes out of the EC2 instances in a region.
_EKS_NODE_TAG_KEYS = ["aws:eks:cluster-name", "eks:cluster-name"]


def count_eks(session, region):
    """Count EKS (Kubernetes) usage in a region.

    Counts three things: the EKS clusters, the node groups within them, and the
    EC2 machines serving as worker nodes -- including nodes that EKS Auto Mode
    manages for you, which AWS normally leaves out of the ordinary instance list.

    Worker nodes are themselves EC2 instances, so the same machine is counted
    once, not once as an EC2 instance and again as a worker node.
    """
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

    total_ng = 0
    for c in clusters:
        ng_token = None
        while True:
            ng_kwargs = {"clusterName": c, "maxResults": 100}
            if ng_token:
                ng_kwargs["nextToken"] = ng_token
            ng_resp = eks.list_nodegroups(**ng_kwargs)
            total_ng += len(ng_resp.get("nodegroups", []))
            ng_token = ng_resp.get("nextToken")
            if not ng_token:
                break

    ec2 = session.client("ec2", region_name=region, config=ADAPTIVE_CFG)
    node_ids = set()
    token, include_managed = None, True
    while True:
        kwargs = {
            "MaxResults": 1000,
            "Filters": [
                {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
                {"Name": "tag-key", "Values": _EKS_NODE_TAG_KEYS},
            ],
        }
        if include_managed:
            kwargs["IncludeManagedResources"] = True
        if token:
            kwargs["NextToken"] = token
        try:
            resp = ec2.describe_instances(**kwargs)
        except ParamValidationError:
            print(f"NOTE: {region}: botocore lacks IncludeManagedResources; EKS Auto Mode "
                  f"nodes not counted (upgrade boto3/botocore to include them)", file=sys.stderr)
            include_managed, token = False, None
            continue
        for res in resp.get("Reservations", []):
            for i in res.get("Instances", []):
                iid = i.get("InstanceId")
                if iid:
                    node_ids.add(iid)
        token = resp.get("NextToken")
        if not token:
            break

    return len(clusters), total_ng, node_ids


def count_for_account(base_session, account_id, account_name, regions, assume_role_name, external_id=None, use_current_session=False):
    """Gather every resource count for one account.

    Counts the account-wide resources (S3, IAM) once, and the per-region
    resources (EC2, Lambda, ECS, EKS) across every region, then adds the regions
    up. The result is one row of numbers for the account.

    If a resource can't be read (for example, a missing permission), its count
    is reported as 0, or as -1 for S3 and IAM to mean "could not be read". If the
    account can't be reached at all, it still appears with zeros and a short note
    explaining why, so one account never hides the rest of the report.
    """
    sts = base_session.client("sts", config=ADAPTIVE_CFG)
    if use_current_session:
        sess = base_session
    else:
        try:
            creds = assume_role(sts, account_id, assume_role_name, external_id)
            sess = get_boto3_session_from_creds(creds)
        except ClientError as e:
            msg = f"AssumeRole failed: {e}"
            print(f"WARNING: account {account_id} {account_name}".rstrip() + f": {msg}; reporting zeros", file=sys.stderr)
            failed = {"account_id": account_id, "account_name": account_name}
            failed.update({k: 0 for k in REGIONAL_FIELDS + GLOBAL_FIELDS})
            failed["error"] = msg
            return failed

    # In org mode the Organizations name is already set; in account mode it's
    # empty, so fall back to the account's IAM alias (if any).
    if not account_name:
        account_name = get_account_alias(sess)

    try:
        s3_count = count_s3(sess)
    except ClientError:
        s3_count = -1
    try:
        iam_users, iam_roles = count_iam(sess)
    except ClientError:
        iam_users, iam_roles = -1, -1

    def region_worker(region):
        """Count every per-region resource (EC2, Lambda, ECS, EKS) in one region.

        The same machine can appear in more than one place: an ECS container
        host or an EKS worker node is itself an EC2 instance. To keep the totals
        honest, a machine counted as a container host or a worker node is not
        also counted as EC2. Machines that only ECS or EKS know about (ECS
        Anywhere hosts and EKS Auto Mode nodes) are not EC2 instances, so they
        are counted on their own.

        If one service can't be read in this region, its count stays 0 and the
        rest of the region is still counted.
        """
        result = {k: 0 for k in REGIONAL_FIELDS}
        try:
            ec2_count, ec2_ids = count_ec2(sess, region)
            result["ec2_standalone"] = ec2_count
        except ClientError:
            ec2_ids = set()
        try:
            result["lambda_functions"] = count_lambda(sess, region)
        except ClientError:
            pass
        try:
            c, s, e2, fg, te2, tfg, ecs_host_ids = count_ecs(sess, region)

            result.update({
                "ecs_clusters": c,
                "ecs_services_total": s,
                "ecs_services_ec2": e2,
                "ecs_services_fargate": fg,
                "ecs_tasks_ec2": te2,
                "ecs_tasks_fargate": tfg,
                "ecs_container_instances": len(ecs_host_ids),
            })

            # A container host that is also an EC2 instance shouldn't add to both
            # totals, so take it out of the EC2 count.
            overlap = ec2_ids & ecs_host_ids

            result["ec2_standalone"] = max(0, result["ec2_standalone"] - len(overlap))
        except ClientError:
            pass
        try:
            kc, ng, eks_node_ids = count_eks(sess, region)
            result.update({"eks_clusters": kc, "eks_nodegroups": ng,
                           "eks_nodes": len(eks_node_ids)})
            # Likewise, a worker node that is also an EC2 instance shouldn't add
            # to both totals, so take it out of the EC2 count. Auto Mode nodes
            # aren't in the EC2 count to begin with, so they stay counted here.
            result["ec2_standalone"] = max(0, result["ec2_standalone"] - len(ec2_ids & eks_node_ids))
        except ClientError:
            pass
        return result

    regional = {k: 0 for k in REGIONAL_FIELDS}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(regions))) as exe:
        for res in exe.map(region_worker, regions):
            for k, v in res.items():
                regional[k] += v

    result = {"account_id": account_id, "account_name": account_name}
    result.update(regional)
    result.update({"s3_buckets": s3_count, "iam_users": iam_users, "iam_roles": iam_roles})
    return result


def main():
    """Run the scan from the command line and print the results.

    Scans either a single account or every account in the organization,
    depending on the options given, and reports the counts as a table, JSON, or
    CSV -- one row per account with a totals line at the end.
    """
    parser = argparse.ArgumentParser(description="Count AWS resources (compute first, then others).", formatter_class=argparse.RawDescriptionHelpFormatter)
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
    parser.add_argument(
        "--write-file", nargs="?", const="", default=None, metavar="PATH",
        help="Write the output to a file instead of stdout (only for --output json/csv; "
             "ignored for table). Give a path, or pass the flag with no value to use an "
             "auto-generated name. Omit the flag entirely to print to stdout (default).",
    )

    args = parser.parse_args()
    started_dt = datetime.now(timezone.utc)
    base = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    caller = base.client("sts", config=ADAPTIVE_CFG).get_caller_identity().get("Account", "")

    targets = []
    if args.mode == "org":
        accts = list_org_accounts(base)
        targets = [(a["Id"], a["Name"]) for a in accts]
    else:
        targets = [(args.account_id or caller, "")]

    regions = args.regions or get_all_regions(base)
    results = [count_for_account(base, aid, name, regions, args.assume_role_name, args.external_id, args.use_current_session or (caller == aid)) for aid, name in targets]

    totals = {k: sum(r.get(k, 0) for r in results if k in r) for k in results[0].keys() if k not in ("account_id", "account_name", "error")}

    # Run-level timing, shared across every output format (UTC, ISO 8601).
    ended_dt = datetime.now(timezone.utc)
    def _iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    scan = {"started_at": _iso(started_dt), "ended_at": _iso(ended_dt)}

    def resolve_outfile(ext):
        """Work out where the output should go.

        Returns a file path when ``--write-file`` was given -- either the path
        you supplied, or an auto-generated, timestamped name -- or None to print
        the results to the screen.
        """
        if args.write_file is None:
            return None
        if args.write_file:
            return args.write_file
        scope = (args.account_id or caller) if args.mode == "account" else "org"
        return f"uptycs_sizing_{scope}_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%SZ')}.{ext}"

    if args.output == "json":
        payload = json.dumps({"scan": scan, "results": results, "totals": totals}, indent=2)
        path = resolve_outfile("json")
        if path:
            with open(path, "w") as f:
                f.write(payload + "\n")
            print(f"Wrote JSON output to {path}", file=sys.stderr)
        else:
            print(payload)
        return

    # The first two columns identify the account and get their own labels on the
    # TOTALS row; the rest come from OUTPUT_FIELDS so all formats stay in sync.
    header = [("Account ID", "account_id", 14), ("Name", "account_name", 20)] + OUTPUT_FIELDS
    data_cols = header[2:]  # everything past the two identity columns

    if args.output == "csv":
        path = resolve_outfile("csv")
        # newline="" is required by the csv module to avoid blank rows when writing
        # to a file; stdout keeps its default handling.
        f = open(path, "w", newline="") if path else sys.stdout
        try:
            writer = csv.writer(f)
            writer.writerow([label for label, _, _ in header])
            for r in results:
                writer.writerow([r[key] for _, key, _ in header])
            writer.writerow(["TOTALS", ""] + [totals[key] for _, key, _ in data_cols])
            writer.writerow(["Scan started", scan["started_at"]])
            writer.writerow(["Scan ended", scan["ended_at"]])
        finally:
            if path:
                f.close()
        if path:
            print(f"Wrote CSV output to {path}", file=sys.stderr)
        return

    if args.write_file is not None:
        print("WARNING: --write-file is only supported for --output json/csv; "
              "printing table to stdout", file=sys.stderr)

    widths = [w for _, _, w in header]
    def fmt(cols): return " ".join(str(c)[:w].ljust(w) for c, w in zip(cols, widths))
    print(fmt([label for label, _, _ in header]))
    print("-" * (sum(widths) + len(widths)))

    for r in results:
        print(fmt([r[key] for _, key, _ in header]))

    print("\nTOTALS:")
    print(fmt(["Accounts", ""] + [totals[key] for _, key, _ in data_cols]))

    print(f"\nScan started: {scan['started_at']}")
    print(f"Scan ended:   {scan['ended_at']}")


if __name__ == "__main__":
    main()
