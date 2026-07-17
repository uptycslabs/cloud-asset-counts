#!/usr/bin/env python3

"""
Uptycs Google Cloud sizing tool.

Counts key Google Cloud compute resources across a single project, or across
every active project your credentials can access, and reports the results as a
table, CSV, or JSON. See README.md for setup and usage.

Version: 1.1.0
"""

import argparse
import concurrent.futures
import csv
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import google.auth
from google.api_core.exceptions import GoogleAPIError
from google.cloud import (
    compute_v1,
    container_v1,
    functions_v2,
    resourcemanager_v3,
    run_v2,
)


def region_of(location: str) -> str:
    """Return the region a Compute Engine location belongs to.

    Locations are either regions (for example ``us-central1``) or zones (for
    example ``us-central1-a``). A zone is a region name followed by a
    single-letter suffix, so the region is recovered by removing that suffix.
    A value that is already a region is returned unchanged.
    """
    if not location:
        return ""
    parts = location.split("-")
    if len(parts) >= 3 and len(parts[-1]) == 1:
        return "-".join(parts[:-1])
    return location


def _is_gke_managed(instance_group_manager_name: str) -> bool:
    """Return True if an instance group backs a GKE node pool.

    GKE creates and manages an instance group for each node pool, named with a
    ``gke-`` prefix. Those machines are reported as GKE nodes, so their groups
    are not also reported as standalone managed instance groups.
    """
    return instance_group_manager_name.startswith("gke-")


def list_regions(credentials, project_id: str) -> List[str]:
    """Return the names of every Compute Engine region available to a project."""
    client = compute_v1.RegionsClient(credentials=credentials)
    return [r.name for r in client.list(project=project_id)]


def count_compute(credentials, project_id: str, regions=None) -> Dict[str, int]:
    """Count Compute Engine virtual machines and managed instance groups.

    Standalone virtual machines are reported separately from managed instance
    groups. A machine that a managed instance group created and owns is counted
    once, as a group instance, and is not also counted as a standalone virtual
    machine.

    The instance groups that back Google Kubernetes Engine node pools are not
    reported here -- those machines are counted as GKE nodes instead -- but they
    are still excluded from the standalone virtual-machine count so that a node
    is never counted twice.

    Args:
        credentials: Google Cloud credentials.
        project_id: The project to count in.
        regions: Optional list of regions to restrict the count to.

    Returns:
        Counts for standalone virtual machines (``vms``), managed instance
        groups (``migs``), and the instances those groups currently manage
        (``mig_instances``).
    """
    region_filter: Optional[Set[str]] = set(regions) if regions else None

    instances_client = compute_v1.InstancesClient(credentials=credentials)
    zonal_migs_client = compute_v1.InstanceGroupManagersClient(credentials=credentials)
    regional_migs_client = compute_v1.RegionInstanceGroupManagersClient(credentials=credentials)

    managed_instance_urls: Set[str] = set()
    migs = 0
    mig_instances = 0

    # instanceGroupManagers.aggregatedList returns both zonal MIGs (under
    # zones/<zone> scopes) and regional MIGs (under regions/<region> scopes), so
    # one project-wide pass covers both. The scope prefix says which client to
    # use to list a group's managed instances -- a regional group must be listed
    # with the regional client, or the API rejects the region as an unknown zone.
    for scope, scoped in zonal_migs_client.aggregated_list(project=project_id):
        managers = getattr(scoped, "instance_group_managers", None) or []
        if not managers:
            continue
        location = scope.split("/")[-1]
        is_regional = scope.startswith("regions/")
        region = location if is_regional else region_of(location)
        if region_filter and region not in region_filter:
            continue
        for manager in managers:
            if is_regional:
                members = regional_migs_client.list_managed_instances(
                    project=project_id, region=location, instance_group_manager=manager.name
                )
            else:
                members = zonal_migs_client.list_managed_instances(
                    project=project_id, zone=location, instance_group_manager=manager.name
                )
            member_count = 0
            for member in members:
                member_count += 1
                if member.instance:
                    managed_instance_urls.add(member.instance)
            if _is_gke_managed(manager.name):
                continue
            migs += 1
            mig_instances += member_count

    vms = 0
    for scope, scoped in instances_client.aggregated_list(project=project_id):
        instances = getattr(scoped, "instances", None) or []
        if not instances:
            continue
        zone = scope.split("/")[-1]
        if region_filter and region_of(zone) not in region_filter:
            continue
        for instance in instances:
            if instance.self_link in managed_instance_urls:
                continue
            vms += 1

    return {"vms": vms, "migs": migs, "mig_instances": mig_instances}


def count_gke(credentials, project_id: str, regions=None) -> Dict[str, int]:
    """Count Google Kubernetes Engine clusters, node pools, and nodes.

    Args:
        credentials: Google Cloud credentials.
        project_id: The project to count in.
        regions: Optional list of regions to restrict the count to.

    Returns:
        Counts for clusters (``gke_clusters``), node pools (``gke_nodepools``),
        and worker nodes (``gke_nodes``).
    """
    region_filter: Optional[Set[str]] = set(regions) if regions else None
    client = container_v1.ClusterManagerClient(credentials=credentials)
    response = client.list_clusters(parent=f"projects/{project_id}/locations/-")

    clusters = nodepools = nodes = 0
    for cluster in response.clusters:
        if region_filter and region_of(cluster.location) not in region_filter:
            continue
        clusters += 1
        nodepools += len(cluster.node_pools)
        nodes += cluster.current_node_count or 0
    return {"gke_clusters": clusters, "gke_nodepools": nodepools, "gke_nodes": nodes}


def count_cloud_run(credentials, project_id: str, regions=None) -> Dict[str, int]:
    """Count Cloud Run services.

    Args:
        credentials: Google Cloud credentials.
        project_id: The project to count in.
        regions: Regions to look in.

    Returns:
        A count of Cloud Run services (``cloud_run_services``).
    """
    client = run_v2.ServicesClient(credentials=credentials)
    services = 0
    skipped_regions = []
    for region in regions or []:
        parent = f"projects/{project_id}/locations/{region}"
        try:
            for _ in client.list_services(parent=parent):
                services += 1
        except GoogleAPIError:
            skipped_regions.append(region)
    if skipped_regions:
        print(
            f"NOTE: project {project_id}: skipped {len(skipped_regions)} region(s) for "
            f"Cloud Run (access denied or unavailable): {', '.join(skipped_regions)}",
            file=sys.stderr,
        )
    return {"cloud_run_services": services}


def count_functions(credentials, project_id: str, regions=None) -> Dict[str, int]:
    """Count Cloud Functions, including both 1st and 2nd generation functions.

    Args:
        credentials: Google Cloud credentials.
        project_id: The project to count in.
        regions: Optional list of regions to restrict the count to.

    Returns:
        A count of Cloud Functions (``cloud_functions``).
    """
    region_filter: Optional[Set[str]] = set(regions) if regions else None
    client = functions_v2.FunctionServiceClient(credentials=credentials)
    count = 0
    for function in client.list_functions(parent=f"projects/{project_id}/locations/-"):
        parts = function.name.split("/")
        location = parts[3] if len(parts) > 3 else ""
        if region_filter and region_of(location) not in region_filter:
            continue
        count += 1
    return {"cloud_functions": count}


# Each entry pairs a counting function with the fields it produces. To add a
# resource type, write a count_* function, add it here, and add its columns to
# COLUMNS below.
COUNTERS: List[Tuple] = [
    (count_compute, ("vms", "migs", "mig_instances")),
    (count_gke, ("gke_clusters", "gke_nodepools", "gke_nodes")),
    (count_cloud_run, ("cloud_run_services",)),
    (count_functions, ("cloud_functions",)),
]

# All numeric fields reported for a project, derived from the counter registry.
COUNT_FIELDS = tuple(field for _, fields in COUNTERS for field in fields)

# Each column is (header label, result key, table column width). This single
# list drives the CSV header/rows and the fixed-width table alike.
COLUMNS = [
    ("Project ID", "project_id", 34),
    ("Name", "project_name", 24),
    ("VMs", "vms", 6),
    ("MIGs", "migs", 6),
    ("MIG-Instances", "mig_instances", 14),
    ("GKE-Clusters", "gke_clusters", 13),
    ("GKE-NodePools", "gke_nodepools", 14),
    ("GKE-Nodes", "gke_nodes", 10),
    ("CloudRun-Services", "cloud_run_services", 18),
    ("Cloud-Functions", "cloud_functions", 16),
]


def list_projects(credentials, organization_id=None) -> List[Dict[str, str]]:
    """List the active projects the current credentials can access.

    When an organization id is given, the list covers every active project in
    that organization, including projects nested inside folders at any depth.

    Args:
        credentials: Google Cloud credentials.
        organization_id: Optional organization id to filter projects by.

    Returns:
        One ``{"id": ..., "name": ...}`` entry per active project.
    """
    projects_client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    if not organization_id:
        return [{"id": p.project_id, "name": p.display_name or ""}
                for p in projects_client.search_projects(query="state:ACTIVE")]

    # Projects sit either directly under the org or nested in folders at any
    # depth, so walk the whole tree: at each node collect its projects and
    # descend into its subfolders. search_projects' parent: filter matches the
    # immediate parent only, which is why a plain org-parent query misses
    # folder-nested projects.
    folders_client = resourcemanager_v3.FoldersClient(credentials=credentials)
    projects, parents, skipped = [], [f"organizations/{organization_id}"], []
    while parents:
        parent = parents.pop()
        try:
            parents.extend(f.name for f in folders_client.list_folders(parent=parent))
            projects.extend(
                {"id": p.project_id, "name": p.display_name or ""}
                for p in projects_client.search_projects(query=f"state:ACTIVE parent:{parent}")
            )
        except GoogleAPIError:
            skipped.append(parent)
    if skipped:
        print(
            f"NOTE: could not read {len(skipped)} organization node(s) "
            f"(access denied or unavailable); projects under them are not counted: "
            f"{', '.join(skipped)}",
            file=sys.stderr,
        )
    return projects


def count_for_project(credentials, project_id, project_name, regions=None) -> Dict:
    """Collect every resource count for a single project.

    Each resource type is counted on its own. If one cannot be read -- for
    example because the relevant API is not enabled, or the credentials lack
    permission -- that resource is reported as 0 and a note is written to
    standard error, while the remaining resources are still counted.

    Args:
        credentials: Google Cloud credentials.
        project_id: The project to count in.
        project_name: The project's display name (may be empty).
        regions: Optional list of regions to restrict the counts to.

    Returns:
        A result containing every count field plus ``project_id`` and
        ``project_name``.
    """
    result = {field: 0 for field in COUNT_FIELDS}
    for counter, fields in COUNTERS:
        try:
            result.update(counter(credentials, project_id, regions))
        except Exception as error:
            label = f"{project_id} {project_name}".rstrip()
            print(
                f"WARNING: project {label}: could not count "
                f"{', '.join(fields)}: {error}; reporting zeros",
                file=sys.stderr,
            )
            for field in fields:
                result[field] = 0
    result.update({"project_id": project_id, "project_name": project_name})
    return result


def main():
    """Parse command-line arguments, count resources, and print the results."""
    parser = argparse.ArgumentParser(
        description="Count Google Cloud compute resources for sizing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--mode", choices=["project", "organization"], required=True)
    parser.add_argument("--project-id")
    parser.add_argument("--organization-id")
    parser.add_argument("--regions", nargs="*")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table")
    parser.add_argument(
        "--write-file",
        nargs="?",
        const="",
        default=None,
        metavar="PATH",
        help="Write the output to a file instead of standard output (JSON or CSV "
        "only; ignored for table). Give a path, or pass the flag with no value to "
        "use an auto-generated name. Omit the flag entirely to print to standard "
        "output (default).",
    )

    args = parser.parse_args()
    started_dt = datetime.now(timezone.utc)
    if args.mode == "project" and not args.project_id:
        parser.error("--mode project requires --project-id")

    credentials, _ = google.auth.default()

    if args.mode == "project":
        targets = [(args.project_id, "")]
    else:
        targets = [(p["id"], p["name"]) for p in list_projects(credentials, args.organization_id)]
        if not targets:
            print("No active projects found for these credentials.", file=sys.stderr)
            sys.exit(1)

    def worker(target):
        project_id, project_name = target
        if args.regions:
            regions = args.regions
        else:
            try:
                regions = list_regions(credentials, project_id)
            except GoogleAPIError as error:
                print(
                    f"WARNING: project {project_id}: could not list regions ({error}); "
                    f"regional services may be undercounted",
                    file=sys.stderr,
                )
                regions = []
        return count_for_project(credentials, project_id, project_name, regions)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(targets))) as executor:
        results = list(executor.map(worker, targets))

    totals = {field: sum(r.get(field, 0) for r in results) for field in COUNT_FIELDS}

    # Run-level timing, shared across every output format (UTC, ISO 8601).
    ended_dt = datetime.now(timezone.utc)
    def _iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    scan = {"started_at": _iso(started_dt), "ended_at": _iso(ended_dt)}

    def resolve_outfile(ext):
        """Return the path to write to, or None to print to standard output."""
        if args.write_file is None:
            return None
        if args.write_file:
            return args.write_file
        scope = args.project_id if args.mode == "project" else "organization"
        return f"uptycs_sizing_gcp_{scope}_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%SZ')}.{ext}"

    if args.output == "json":
        payload = json.dumps({"scan": scan, "results": results, "totals": totals}, indent=2)
        path = resolve_outfile("json")
        if path:
            with open(path, "w") as handle:
                handle.write(payload + "\n")
            print(f"Wrote JSON output to {path}", file=sys.stderr)
        else:
            print(payload)
        return

    data_cols = COLUMNS[2:]  # everything past the two identity columns

    if args.output == "csv":
        path = resolve_outfile("csv")
        handle = open(path, "w", newline="") if path else sys.stdout
        try:
            writer = csv.writer(handle)
            writer.writerow([label for label, _, _ in COLUMNS])
            for r in results:
                writer.writerow([r[key] for _, key, _ in COLUMNS])
            writer.writerow(["TOTALS", ""] + [totals[key] for _, key, _ in data_cols])
            writer.writerow(["Scan started", scan["started_at"]])
            writer.writerow(["Scan ended", scan["ended_at"]])
        finally:
            if path:
                handle.close()
        if path:
            print(f"Wrote CSV output to {path}", file=sys.stderr)
        return

    if args.write_file is not None:
        print(
            "WARNING: --write-file is only supported for --output json/csv; "
            "printing table to standard output",
            file=sys.stderr,
        )

    widths = [w for _, _, w in COLUMNS]

    def fmt(cols):
        return " ".join(str(c)[:w].ljust(w) for c, w in zip(cols, widths))

    print(fmt([label for label, _, _ in COLUMNS]))
    print("-" * (sum(widths) + len(widths)))
    for r in results:
        print(fmt([r[key] for _, key, _ in COLUMNS]))

    print("\nTOTALS:")
    print(fmt(["Projects", ""] + [totals[key] for _, key, _ in data_cols]))

    print(f"\nScan started: {scan['started_at']}")
    print(f"Scan ended:   {scan['ended_at']}")


if __name__ == "__main__":
    main()
