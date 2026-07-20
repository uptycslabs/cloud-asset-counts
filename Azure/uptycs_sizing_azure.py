#!/usr/bin/env python3

"""
Please refer README.md for more information on how to use the script

Version: 1.0
"""

import argparse
import concurrent.futures
import csv
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.appcontainers import ContainerAppsAPIClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient


def rg_from_id(resource_id: str) -> str:
    """Extract the resource group name from an ARM resource id.

    ARM ids look like ``/subscriptions/<sub>/resourceGroups/<rg>/providers/...``.
    Some ops (e.g. listing VMSS instances) need the resource group but only the
    full id is available on the parent object.

    Args:
        resource_id: Full ARM resource id.

    Returns:
        str: The resource group name, or "" if it can't be parsed.
    """
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def count_vms(credential, subscription_id: str, locations=None) -> Dict[str, int]:
    """Count standalone Virtual Machines in a subscription.

    Uses the subscription-wide ``virtual_machines.list_all()`` (ARM list APIs are
    not region-scoped). VMs that belong to a Flexible-orchestration scale set are
    excluded here and counted under VMSS instead (``virtual_machine_scale_set`` is
    set on such VMs); Uniform scale-set instances never appear in this listing.

    Args:
        credential: An azure-identity credential.
        subscription_id: Target subscription id.
        locations: Optional set of location names to restrict the count to.

    Returns:
        dict: ``{"vms": <int>}``.
    """
    client = ComputeManagementClient(credential, subscription_id)
    count = 0
    for vm in client.virtual_machines.list_all():
        if getattr(vm, "virtual_machine_scale_set", None) is not None:
            continue
        if locations and (vm.location or "").lower() not in locations:
            continue
        count += 1
    return {"vms": count}


# Tag AKS puts on every node-pool scale set it manages; used to exclude AKS
# worker nodes from the generic VMSS bucket (they are counted under AKS instead).
_AKS_MANAGED_VMSS_TAG = "aks-managed-poolName"


def count_vmss(credential, subscription_id: str, locations=None) -> Dict[str, int]:
    """Count standalone VM Scale Sets and their live instances in a subscription.

    ``vmss_instances`` counts the instances that actually exist
    (``virtual_machine_scale_set_vms.list``) rather than the configured
    ``sku.capacity``, which is a desired value that can lag reality.

    AKS node pools are implemented as scale sets (tagged
    ``aks-managed-poolName``, living in the cluster's ``MC_...`` node resource
    group); those are excluded here and counted under AKS instead, so a machine
    is never counted both as a generic VMSS instance and an AKS node.

    Args:
        credential: An azure-identity credential.
        subscription_id: Target subscription id.
        locations: Optional set of location names to restrict the count to.

    Returns:
        dict: ``{"vmss": <int>, "vmss_instances": <int>}``.
    """
    client = ComputeManagementClient(credential, subscription_id)
    sets = instances = 0
    for ss in client.virtual_machine_scale_sets.list_all():
        if locations and (ss.location or "").lower() not in locations:
            continue
        if (ss.tags or {}).get(_AKS_MANAGED_VMSS_TAG) is not None:
            continue
        sets += 1
        rg = rg_from_id(ss.id)
        if rg:
            instances += sum(1 for _ in client.virtual_machine_scale_set_vms.list(rg, ss.name))
    return {"vmss": sets, "vmss_instances": instances}


def count_aks(credential, subscription_id: str, locations=None) -> Dict[str, int]:
    """Count AKS clusters, agent pools (node pools), and nodes in a subscription.

    Node count is the sum of each pool's **live** ``count`` from the per-pool
    ``agent_pools.list`` endpoint, which reflects autoscaler-added nodes. The
    cluster-summary ``agent_pool_profiles[].count`` is the configured/model value
    that goes stale when the autoscaler grows a pool, so it is only used as a
    per-cluster fallback if the per-pool call fails. Virtual-node /
    Node-Autoprovisioning nodes remain a blind spot.

    Args:
        credential: An azure-identity credential.
        subscription_id: Target subscription id.
        locations: Optional set of location names to restrict the count to.

    Returns:
        dict: ``{"aks_clusters": <int>, "aks_nodepools": <int>, "aks_nodes": <int>}``.
    """
    client = ContainerServiceClient(credential, subscription_id)
    clusters = nodepools = nodes = 0
    for c in client.managed_clusters.list():
        if locations and (c.location or "").lower() not in locations:
            continue
        clusters += 1
        try:
            pools = list(client.agent_pools.list(rg_from_id(c.id), c.name))
        except HttpResponseError:
            pools = c.agent_pool_profiles or []
        for pool in pools:
            nodepools += 1
            nodes += pool.count or 0
    return {"aks_clusters": clusters, "aks_nodepools": nodepools, "aks_nodes": nodes}


def count_aci(credential, subscription_id: str, locations=None) -> Dict[str, int]:
    """Count Azure Container Instances (container groups and containers).

    Args:
        credential: An azure-identity credential.
        subscription_id: Target subscription id.
        locations: Optional set of location names to restrict the count to.

    Returns:
        dict: ``{"aci_groups": <int>, "aci_containers": <int>}``.
    """
    client = ContainerInstanceManagementClient(credential, subscription_id)
    groups = containers = 0
    for g in client.container_groups.list():
        if locations and (g.location or "").lower() not in locations:
            continue
        groups += 1
        containers += len(g.containers or [])
    return {"aci_groups": groups, "aci_containers": containers}


def count_appservice(credential, subscription_id: str, locations=None) -> Dict[str, int]:
    """Count Azure Functions vs App Service web apps in a subscription.

    ``web_apps.list()`` returns function apps, web apps, and other site kinds
    together; they are split on the ``kind`` field (function apps contain
    "functionapp"). Consumption-plan function apps are serverless (no worker
    count), a blind spot analogous to AWS Lambda.

    Args:
        credential: An azure-identity credential.
        subscription_id: Target subscription id.
        locations: Optional set of location names to restrict the count to.

    Returns:
        dict: ``{"functions": <int>, "web_apps": <int>}``.
    """
    client = WebSiteManagementClient(credential, subscription_id)
    functions = web_apps = 0
    for site in client.web_apps.list():
        if locations and (site.location or "").replace(" ", "").lower() not in locations:
            continue
        if "functionapp" in (site.kind or ""):
            functions += 1
        else:
            web_apps += 1
    return {"functions": functions, "web_apps": web_apps}


def count_container_apps(credential, subscription_id: str, locations=None) -> Dict[str, int]:
    """Count Azure Container Apps and their managed environments in a subscription.

    Replica counts are KEDA-driven and dynamic, so only app and environment
    counts are reported.

    Args:
        credential: An azure-identity credential.
        subscription_id: Target subscription id.
        locations: Optional set of location names to restrict the count to.

    Returns:
        dict: ``{"container_apps": <int>, "container_app_envs": <int>}``.
    """
    client = ContainerAppsAPIClient(credential, subscription_id)
    apps = envs = 0
    for app in client.container_apps.list_by_subscription():
        if locations and (app.location or "").replace(" ", "").lower() not in locations:
            continue
        apps += 1
    for env in client.managed_environments.list_by_subscription():
        if locations and (env.location or "").replace(" ", "").lower() not in locations:
            continue
        envs += 1
    return {"container_apps": apps, "container_app_envs": envs}


# Modular counter registry. Each entry pairs a counter function with the fields
# it produces. subscription_worker() runs every counter and, if one raises, zero-
# fills ONLY that counter's fields -- so a single failing service can't blank out
# the rest of the row. To add a resource type: write a count_* fn, add it here,
# and add its columns to COLUMNS below. Those two lists are the only places that
# need to know about a new resource.
COUNTERS: List[Tuple] = [
    (count_vms, ("vms",)),
    (count_vmss, ("vmss", "vmss_instances")),
    (count_aks, ("aks_clusters", "aks_nodepools", "aks_nodes")),
    (count_aci, ("aci_groups", "aci_containers")),
    (count_appservice, ("functions", "web_apps")),
    (count_container_apps, ("container_apps", "container_app_envs")),
]

# All per-subscription numeric fields, derived from the registry so it can never
# drift from COUNTERS.
REGIONAL_FIELDS = tuple(f for _, fields in COUNTERS for f in fields)

# Each column is (header label, result-dict key, table column width). This one
# list drives the CSV header/rows and the fixed-width table alike, so the column
# set and ordering can't drift between the two renderings.
COLUMNS = [
    ("Subscription ID", "subscription_id", 38), ("Name", "subscription_name", 24),
    ("VMs", "vms", 6), ("VMSS", "vmss", 6), ("VMSS-Instances", "vmss_instances", 15),
    ("AKS-Clusters", "aks_clusters", 13), ("AKS-NodePools", "aks_nodepools", 14),
    ("AKS-Nodes", "aks_nodes", 10), ("ACI-Groups", "aci_groups", 11),
    ("ACI-Containers", "aci_containers", 15), ("Functions", "functions", 10),
    ("Web-Apps", "web_apps", 9), ("Container-Apps", "container_apps", 15),
    ("ContainerApp-Envs", "container_app_envs", 18),
]


def list_subscriptions(credential, tenant_id=None) -> List[Dict[str, str]]:
    """List all ENABLED subscriptions the credential can access.

    Disabled/warned/deleted subscriptions are skipped so per-subscription API
    calls don't fail. When ``tenant_id`` is given, results are limited to that
    tenant.

    Args:
        credential: An azure-identity credential.
        tenant_id: Optional tenant id to filter subscriptions by.

    Returns:
        list[dict]: One ``{"id": ..., "name": ...}`` per enabled subscription.
    """
    client = SubscriptionClient(credential)
    subs = []
    for s in client.subscriptions.list():
        if s.state and str(s.state) not in ("Enabled", "SubscriptionState.ENABLED"):
            continue
        if tenant_id and s.tenant_id and s.tenant_id != tenant_id:
            continue
        subs.append({"id": s.subscription_id, "name": s.display_name or ""})
    return subs


def count_for_subscription(credential, subscription_id, subscription_name, locations=None):
    """Collect all compute counts for a single subscription.

    Runs every counter in COUNTERS. Error behavior mirrors the AWS script's
    per-service tolerance: if a counter raises ``HttpResponseError`` its fields
    contribute 0 and the rest of the row still renders. A total auth failure for
    the subscription is not special-cased here -- individual counters will each
    fail and zero-fill, and the subscription still appears in the output.

    Args:
        credential: An azure-identity credential.
        subscription_id: Target subscription id.
        subscription_name: Display name (may be empty).
        locations: Optional set of lowercased location names to restrict counts to.

    Returns:
        dict: All REGIONAL_FIELDS plus ``subscription_id``/``subscription_name``.
    """
    result = {k: 0 for k in REGIONAL_FIELDS}
    for fn, fields in COUNTERS:
        try:
            result.update(fn(credential, subscription_id, locations))
        except HttpResponseError as e:
            print(f"WARNING: subscription {subscription_id} {subscription_name}".rstrip()
                  + f": {fn.__name__} failed: {e.message if hasattr(e, 'message') else e}; reporting zeros",
                  file=sys.stderr)
            for f in fields:
                result[f] = 0
    result.update({"subscription_id": subscription_id, "subscription_name": subscription_name})
    return result


def main():
    """CLI entry point: parse args, resolve subscriptions, count, and render.

    Targets are either a single subscription (``--mode subscription``) or every
    enabled subscription the credential can see (``--mode tenant``). Compute counts
    render as JSON or a fixed-width table/CSV with one row per subscription and a
    TOTALS footer.
    """
    parser = argparse.ArgumentParser(
        description="Count Azure compute resources for sizing.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["subscription", "tenant"], required=True)
    parser.add_argument("--subscription-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--locations", nargs="*")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table")
    parser.add_argument(
        "--write-file", nargs="?", const="", default=None, metavar="PATH",
        help="Write the output to a file instead of stdout (only for --output json/csv; "
             "ignored for table). Give a path, or pass the flag with no value to use an "
             "auto-generated name. Omit the flag entirely to print to stdout (default).",
    )

    args = parser.parse_args()
    started_dt = datetime.now(timezone.utc)
    if args.mode == "subscription" and not args.subscription_id:
        parser.error("--mode subscription requires --subscription-id")

    credential = DefaultAzureCredential()

    if args.mode == "subscription":
        targets = [(args.subscription_id, "")]
    else:
        targets = [(s["id"], s["name"]) for s in list_subscriptions(credential, args.tenant_id)]
        if not targets:
            print("No enabled subscriptions found for this credential.", file=sys.stderr)
            sys.exit(1)

    locations = {loc.replace(" ", "").lower() for loc in args.locations} if args.locations else None

    def worker(target):
        sid, name = target
        return count_for_subscription(credential, sid, name, locations)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(targets))) as exe:
        results = list(exe.map(worker, targets))

    totals = {k: sum(r.get(k, 0) for r in results) for k in REGIONAL_FIELDS}

    # Run-level timing, shared across every output format (UTC, ISO 8601).
    ended_dt = datetime.now(timezone.utc)
    def _iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    scan = {"started_at": _iso(started_dt), "ended_at": _iso(ended_dt)}

    def resolve_outfile(ext):
        """Return the path to write to, or None to print to stdout.

        ``--write-file`` absent -> None (stdout). Passed with a path -> that path.
        Passed bare -> an auto-generated name scoped to the run.
        """
        if args.write_file is None:
            return None
        if args.write_file:
            return args.write_file
        scope = args.subscription_id if args.mode == "subscription" else "tenant"
        return f"uptycs_sizing_azure_{scope}_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%SZ')}.{ext}"

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

    data_cols = COLUMNS[2:]  # everything past the two identity columns

    if args.output == "csv":
        path = resolve_outfile("csv")
        # newline="" is required by the csv module to avoid blank rows when writing
        # to a file; stdout keeps its default handling.
        f = open(path, "w", newline="") if path else sys.stdout
        try:
            writer = csv.writer(f)
            writer.writerow([label for label, _, _ in COLUMNS])
            for r in results:
                writer.writerow([r[key] for _, key, _ in COLUMNS])
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

    widths = [w for _, _, w in COLUMNS]
    def fmt(cols): return " ".join(str(c)[:w].ljust(w) for c, w in zip(cols, widths))
    print(fmt([label for label, _, _ in COLUMNS]))
    print("-" * (sum(widths) + len(widths)))

    for r in results:
        print(fmt([r[key] for _, key, _ in COLUMNS]))

    print("\nTOTALS:")
    print(fmt(["Subscriptions", ""] + [totals[key] for _, key, _ in data_cols]))

    print(f"\nScan started: {scan['started_at']}")
    print(f"Scan ended:   {scan['ended_at']}")


if __name__ == "__main__":
    main()
