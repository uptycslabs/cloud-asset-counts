# Google Cloud Resource Counter (`uptycs_sizing_gcp.py`)

Count key Google Cloud compute resources across a single project, or across every **active**
project your credentials can access. Results are printed as a **table**, **CSV**, or **JSON**
(to your screen or to a file).

Resources counted:

- **Compute Engine** — standalone virtual machines
- **Managed Instance Groups** — groups and the instances they currently manage
- **Google Kubernetes Engine (GKE)** — clusters, node pools, and worker nodes
- **Cloud Run** — services
- **Cloud Functions** — functions (1st and 2nd generation)

### Counted once, never twice

A virtual machine that belongs to a managed instance group is reported under **MIG-Instances** and
is **not** also counted under **VMs**, so no machine is counted twice.

### Known blind spots

- **GKE nodes** are reported as the number of nodes each cluster currently has. Clusters that scale
  their node count automatically, and **Autopilot** clusters (which do not expose a fixed node count),
  can make this an approximate, point-in-time figure.
- **Cloud Run** scales the number of running instances up and down automatically, so only the number
  of services is reported, not the number of running instances.

---

## Features

- 🏢 **Organization-wide mode**: count across every **active** project your credentials can access.
- 🔎 **Single-project mode**: count within one project.
- 🧮 **De-duplicated virtual machines**: managed-instance-group members are not double-counted as VMs.
- 🧵 **Parallel** project scans (up to 16 at a time).
- 🧾 **Multiple output formats**: table, CSV, and JSON — to your screen or to a file.
- 🛟 **Resilient**: if one resource type can't be read, it is reported as `0` and the rest of the row
  is still reported.

> **Note on the table view:** the column widths are fixed so that rows stay aligned in a plain console.

---

## Requirements

- Python **3.10+**
- Packages (pinned in [`requirements.txt`](requirements.txt)):

```text
google-auth
google-cloud-resource-manager
google-cloud-compute
google-cloud-container
google-cloud-run
google-cloud-functions
```

Install them with:

```bash
pip install -r requirements.txt
```

---

## Setup & Authentication

The tool uses **Application Default Credentials (ADC)** — the standard way Google Cloud client
libraries find your credentials. Set them up with **either**:

- **Your user account**:

  ```bash
  gcloud auth application-default login
  ```

- **A service account key** — point an environment variable at the key file:

  ```bash
  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
  ```

Then run:

```bash
pip install -r requirements.txt
python3 uptycs_sizing_gcp.py --mode project --project-id my-project-id --output table
```

> **Note:** `gcloud auth application-default login` is different from `gcloud auth login`. The first
> sets up the credentials this tool reads; the second only signs the `gcloud` command-line tool in.
> If the tool reports an authentication error, run `gcloud auth application-default login`.

### GCP permissions

- The **Viewer** role (`roles/viewer`) on each project you want to count is enough for every listing
  the tool performs.
- For **organization-wide** runs, the account also needs permission to list projects across the
  organization — for example the **Browser** (`roles/browser`) or a Viewer role granted at the
  organization or folder level.
- Each service's API must be **enabled** on the project (Compute Engine, Kubernetes Engine, Cloud Run,
  Cloud Functions). A service whose API is disabled is reported as `0`.

---

## Usage

```text
usage: uptycs_sizing_gcp.py --mode {project,organization} [options]

Required (choose a mode):
  --mode project --project-id <ID>
  --mode organization

Common options:
  --organization-id <ID>            (optional; limit to one organization)
  --regions us-central1 europe-west1 ...   (optional; default: all regions)
  --output {table,json,csv}         (default: table)
  --write-file [PATH]               (json/csv only; auto-names if PATH omitted)
```

### Examples

```bash
# Single project
python3 uptycs_sizing_gcp.py --mode project \
  --project-id my-project-id \
  --output table

# Every active project the credentials can access
python3 uptycs_sizing_gcp.py --mode organization --output json

# Limit to one organization
python3 uptycs_sizing_gcp.py --mode organization \
  --organization-id 123456789012 --output table

# Limit to specific regions and write CSV to an auto-named file
python3 uptycs_sizing_gcp.py --mode project \
  --project-id my-project-id \
  --regions us-central1 europe-west1 --output csv --write-file
```

#### More examples — running with `uv` (no venv needed)

[`uv`](https://docs.astral.sh/uv/) can run the tool in one shot with dependencies resolved, without
creating or activating a virtual environment.

**Requirements:**

- `uv` installed. If you don't have it:

  ```bash
  # macOS / Linux
  curl -LsSf https://astral.sh/uv/install.sh | sh

  # or via pip
  pip install uv
  ```

- `uv` provides Python automatically, so no separate Python install is required.
- Valid Google Cloud credentials in your environment, same as any other run.

```bash
# Run in one shot with dependencies resolved, without activating a venv
uv run --with-requirements requirements.txt python3 uptycs_sizing_gcp.py \
  --mode project --project-id my-project-id --output json
```

---

## Output

The same set of columns drives the table and CSV, so they always match:

| Column            | Key                  | Meaning                                              |
| ----------------- | -------------------- | ---------------------------------------------------- |
| Project ID        | `project_id`         | The project counted                                  |
| Name              | `project_name`       | Project display name (organization mode)             |
| VMs               | `vms`                | Standalone virtual machines (group members excluded) |
| MIGs              | `migs`               | Managed instance groups                              |
| MIG-Instances     | `mig_instances`      | Instances managed by managed instance groups         |
| GKE-Clusters      | `gke_clusters`       | GKE clusters                                         |
| GKE-NodePools     | `gke_nodepools`      | GKE node pools                                       |
| GKE-Nodes         | `gke_nodes`          | GKE worker nodes                                     |
| CloudRun-Services | `cloud_run_services` | Cloud Run services                                   |
| Cloud-Functions   | `cloud_functions`    | Cloud Functions (1st and 2nd generation)             |

### Table (default)

A fixed-width table is printed to your screen, with a `TOTALS` line at the end. It is wide, so the raw
console output may wrap in a narrow terminal. The same data is shown below as a table for readability:

| Project ID     | Name    | VMs | MIGs | MIG-Instances | GKE-Clusters | GKE-NodePools | GKE-Nodes | CloudRun-Services | Cloud-Functions |
| -------------- | ------- | --- | ---- | ------------- | ------------ | ------------- | --------- | ----------------- | --------------- |
| prod-project   | prod    | 8   | 2    | 6             | 3            | 5             | 12        | 4                 | 9               |
| sandbox-project| sandbox | 1   | 0    | 0             | 0            | 0             | 0         | 1                 | 2               |
| **TOTALS**     |         | 9   | 2    | 6             | 3            | 5             | 12        | 5                 | 11              |

### CSV

The header row matches the columns above; the final data row is a **TOTALS** summary.
Use `--write-file [PATH]` to write to a file instead of your screen.

### JSON

`results` is one object per project; `totals` aggregates the counts:

```json
{
  "results": [
    {
      "vms": 8,
      "migs": 2,
      "mig_instances": 6,
      "gke_clusters": 3,
      "gke_nodepools": 5,
      "gke_nodes": 12,
      "cloud_run_services": 4,
      "cloud_functions": 9,
      "project_id": "prod-project",
      "project_name": "prod"
    }
  ],
  "totals": {
    "vms": 8,
    "migs": 2,
    "mig_instances": 6,
    "gke_clusters": 3,
    "gke_nodepools": 5,
    "gke_nodes": 12,
    "cloud_run_services": 4,
    "cloud_functions": 9
  }
}
```

Use `--write-file [PATH]` to save the JSON to a file. With no path, the file is auto-named
`uptycs_sizing_gcp_<scope>_<timestamp>.json`.

---

## How It Works (High Level)

1. **Authenticate** using Application Default Credentials.
2. **Find the projects to count**
   - **Project mode**: uses `--project-id`.
   - **Organization mode**: lists every **active** project the credentials can access (optionally
     limited to one organization with `--organization-id`).
3. **Count** (projects are scanned in parallel, up to 16 at a time): virtual machines and managed
   instance groups, GKE clusters/node pools/nodes, Cloud Run services, and Cloud Functions.
   Managed-instance-group members are excluded from the virtual-machine count so nothing is
   counted twice.
4. **Aggregate totals** and print the results in the format you chose.

---

## Performance & Limits

- **Concurrency**: up to 16 projects are counted in parallel.
- **Throttling**: the Google Cloud client libraries automatically retry transient errors with backoff.
- **Resilience**: if a resource type can't be read for a project (for example, its API is disabled),
  it is reported as `0` and the rest of the counts are still reported.
- **Regions**: Cloud Run is counted per region, so a run covers every region unless you narrow it with
  `--regions`.

---

## Troubleshooting

- **Authentication / credentials error**
  - Run `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to a valid
    service account key. Remember that `gcloud auth login` alone does not set up the credentials this
    tool uses.

- **A resource shows `0` when you expect more**
  - The service's API may not be enabled on that project, or the credentials may lack the Viewer role
    there. A read failure for one resource is noted on standard error and reported as `0`.

- **No projects found (organization mode)**
  - The credentials cannot list any active projects. Check the role assignments, and `--organization-id`
    if you supplied one.

---

## Security Notes

- The tool does not print credentials or secrets.
- Files written with `--write-file` contain project IDs, names, and counts — store them appropriately.
