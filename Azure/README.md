# Azure Resource Counter (`uptycs_sizing_azure.py`)

Count key Azure compute resources across a single subscription or every **enabled** subscription
your credential can see (tenant-wide).
Outputs in **table**, **CSV**, or **JSON** (to stdout or to a file).

Resources counted:

- **Virtual Machines** — every existing VM (deleted VMs don't appear; deallocated VMs are still counted). VMs that belong to a scale set are reported under VMSS, not here.
- **VM Scale Sets** — scale sets and their live **instances**
- **AKS** — clusters, node pools, and worker **nodes**
- **Azure Container Instances** — container groups and **containers**
- **App Service** — **Functions** and **Web Apps** (split by site kind)
- **Container Apps** — apps and managed **environments**

Azure ARM list APIs are **subscription-wide** (not per-region), so the script iterates
**subscriptions** the way the AWS script iterates regions — each subscription is scanned in
one pass and totals are aggregated. Pass `--locations` to restrict counts to specific regions.

### Counted once, never twice

A machine that belongs to a **VM Scale Set** is reported under `VMSS-Instances` and excluded
from the standalone `VMs` count, so no instance is counted twice. (Uniform scale-set instances
never appear as standalone VMs; Flexible-orchestration members are filtered out explicitly.)

### Known blind spots

- **AKS** node counts come from each pool's `count` (or `max_count` isn't used — the last-known value is reported). Cluster-autoscaler churn, **virtual nodes** (ACI-backed), and **Node Autoprovisioning** nodes are not represented; exact live counts require the cluster's Kubernetes API.
- **Functions** on a Consumption plan and **Container Apps** are serverless — their worker/replica counts are dynamic, so only the app/environment counts are reported.

---

## Features

- 🏢 **Tenant-wide mode**: enumerate all **enabled** subscriptions the credential can access.
- 🔎 **Single-subscription mode**: count in one subscription.
- 🧩 **Modular**: a small counter registry drives which resources are counted and the output columns — adding a resource type is a one-line change.
- 🧮 **De-duplicated VMs**: scale-set instances are not double-counted as VMs.
- 🧵 **Parallel per-subscription** scans (up to 16 workers).
- 🧾 **Multiple output formats**: table (pretty), CSV, JSON — printed to stdout or written to a file.
- 🛟 **Resilient**: a per-service failure contributes `0` and the rest of the row still renders.

> **Note on the table view:** the column widths are intentionally fixed in the code to keep alignment consistent in a plain console.

---

## Requirements

- Python **3.10+**
- Packages (pinned in [`requirements.txt`](requirements.txt)):

```text
azure-identity
azure-mgmt-resource-subscriptions
azure-mgmt-compute
azure-mgmt-containerservice
azure-mgmt-containerinstance
azure-mgmt-web
azure-mgmt-appcontainers
```

Install them with:

```bash
pip install -r requirements.txt
```

---

## Setup & Authentication

Authenticate with **either**:

- **Azure CLI** — `az login` (optionally `az account set --subscription <id>`), or
- **Service principal** — export `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.

The script uses `DefaultAzureCredential`, which picks up either automatically.

```bash
pip install -r requirements.txt
az login
python3 uptycs_sizing_azure.py --mode subscription \
  --subscription-id 00000000-0000-0000-0000-000000000000 --output table
```

### Azure permissions

- The built-in **Reader** role on each target subscription. That alone covers every
  compute/resource listing the script performs.

> **Credential precedence gotcha:** `DefaultAzureCredential` tries the **environment**
> service principal (`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET`) **before**
> your `az login` session. If those variables are set (common on shared dev machines) but point
> at a different tenant/app, the run fails there and never falls back to the CLI login. Unset
> them (`unset AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_CLIENT_SECRET`) to force the CLI login.

---

## Usage

```text
usage: uptycs_sizing_azure.py --mode {subscription,tenant} [options]

Required (choose a mode):
  --mode subscription --subscription-id <ID>
  --mode tenant

Common options:
  --tenant-id <ID>                 (optional; scopes subscription enumeration)
  --locations eastus westus2 ...   (optional; default: all regions)
  --output {table,json,csv}        (default: table)
  --write-file [PATH]              (json/csv only; auto-names if PATH omitted)
```

### Examples

```bash
# Single subscription, using az login
python3 uptycs_sizing_azure.py --mode subscription \
  --subscription-id 00000000-0000-0000-0000-000000000000 \
  --output table

# Tenant-wide (every enabled subscription the credential can see)
python3 uptycs_sizing_azure.py --mode tenant --output json

# Tenant-wide via a service principal (env vars set)
AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... \
  python3 uptycs_sizing_azure.py --mode tenant --output table

# Limit to specific regions and write CSV to an auto-named file
python3 uptycs_sizing_azure.py --mode subscription \
  --subscription-id 00000000-0000-0000-0000-000000000000 \
  --locations eastus westus2 --output csv --write-file
```

#### More examples — running with `uv` (no venv needed)

[`uv`](https://docs.astral.sh/uv/) can run the script in one shot with dependencies resolved, without creating or activating a virtual environment.

**Requirements:**

- `uv` installed. If you don't have it:

  ```bash
  # macOS / Linux
  curl -LsSf https://astral.sh/uv/install.sh | sh

  # or via pip
  pip install uv
  ```

- `uv` provides Python automatically, so no separate Python install is required.
- Valid Azure credentials in your environment (`az login` or a service principal), same as any other run.

```bash
# Run in one shot with dependencies resolved, without activating a venv
uv run --with-requirements requirements.txt python3 uptycs_sizing_azure.py \
  --mode subscription --subscription-id 00000000-0000-0000-0000-000000000000 --output json
```

---

## Output

The same set of columns drives the table and CSV, so they always match:

| Column            | Key                  | Meaning                                       |
| ----------------- | -------------------- | --------------------------------------------- |
| Subscription ID   | `subscription_id`    | Target subscription                           |
| Name              | `subscription_name`  | Subscription display name (tenant mode)       |
| VMs               | `vms`                | Standalone VMs (scale-set instances excluded) |
| VMSS              | `vmss`               | VM Scale Sets                                 |
| VMSS-Instances    | `vmss_instances`     | Live scale-set instances                      |
| AKS-Clusters      | `aks_clusters`       | AKS clusters                                  |
| AKS-NodePools     | `aks_nodepools`      | AKS agent pools                               |
| AKS-Nodes         | `aks_nodes`          | AKS worker nodes (sum of pool counts)         |
| ACI-Groups        | `aci_groups`         | Azure Container Instance groups               |
| ACI-Containers    | `aci_containers`     | Containers across all ACI groups              |
| Functions         | `functions`          | Function apps                                 |
| Web-Apps          | `web_apps`           | App Service web apps (non-function sites)     |
| Container-Apps    | `container_apps`     | Azure Container Apps                          |
| ContainerApp-Envs | `container_app_envs` | Container Apps managed environments           |

### Table (default)

A fixed-width table is printed to stdout, with a `TOTALS` line and a scan-timing footer (UTC start/end) at the end. It is wide (14 columns), so the raw console output wraps in a narrow terminal. The same data is shown below as a table for readability:

| Subscription ID | Name    | VMs | VMSS | VMSS-Instances | AKS-Clusters | AKS-NodePools | AKS-Nodes | ACI-Groups | ACI-Containers | Functions | Web-Apps | Container-Apps | ContainerApp-Envs |
| --------------- | ------- | --- | ---- | -------------- | ------------ | ------------- | --------- | ---------- | -------------- | --------- | -------- | -------------- | ----------------- |
| 8da31d20-...    | prod    | 5   | 5    | 6              | 3            | 5             | 6         | 10         | 19             | 4         | 2        | 1              | 1                 |
| 77ec1fed-...    | sandbox | 1   | 0    | 0              | 0            | 0             | 0         | 0          | 0              | 2         | 1        | 0              | 0                 |
| **TOTALS**      |         | 6   | 5    | 6              | 3            | 5             | 6         | 10         | 19             | 6         | 3        | 1              | 1                 |

The footer reports when the scan started and ended (UTC):

```
Scan started: 2026-07-14T09:00:01Z
Scan ended:   2026-07-14T09:02:14Z
```

### CSV

The header row matches the columns above; then one row per subscription, a **TOTALS** summary row, and two trailing scan-timing rows (`Scan started`, `Scan ended`).
Use `--write-file [PATH]` to write to a file instead of stdout.

### JSON

`scan` holds run timing; `results` is one object per subscription; `totals` aggregates the compute fields:

```json
{
  "scan": {
    "started_at": "2026-07-14T09:00:01Z",
    "ended_at": "2026-07-14T09:02:14Z"
  },
  "results": [
    {
      "vms": 5,
      "vmss": 5,
      "vmss_instances": 6,
      "aks_clusters": 3,
      "aks_nodepools": 5,
      "aks_nodes": 6,
      "aci_groups": 10,
      "aci_containers": 19,
      "functions": 4,
      "web_apps": 2,
      "container_apps": 1,
      "container_app_envs": 1,
      "subscription_id": "8da31d20-...",
      "subscription_name": "Sponsors"
    }
  ],
  "totals": {
    "vms": 5,
    "vmss": 5,
    "vmss_instances": 6,
    "aks_clusters": 3,
    "aks_nodepools": 5,
    "aks_nodes": 6,
    "aci_groups": 10,
    "aci_containers": 19,
    "functions": 4,
    "web_apps": 2,
    "container_apps": 1,
    "container_app_envs": 1
  }
}
```

Use `--write-file [PATH]` to save the JSON to a file. With no path, the file is auto-named
`uptycs_sizing_azure_<scope>_<timestamp>.json` (timestamp in UTC).

---

## How It Works (High Level)

1. **Authenticate** with `DefaultAzureCredential` (Azure CLI or service principal).
2. **Target discovery**
   - **Subscription mode**: uses `--subscription-id`.
   - **Tenant mode**: `SubscriptionClient.subscriptions.list()` → **enabled** subscriptions only.
3. **Count** (subscriptions scanned in parallel, up to 16 workers): each counter runs a
   subscription-wide list call — VMs, VMSS (+ instances), AKS (clusters/pools/nodes), ACI
   (groups/containers), App Service (functions/web apps), Container Apps (+ environments).
   Scale-set instances are subtracted from the VM count so nothing is double-counted.
4. **Aggregate totals** and print/output in the selected format.

---

## Performance & Limits

- **Concurrency**: up to 16 parallel per-subscription workers.
- **Throttling**: the Azure SDK retries transient failures automatically via the default
  `azure-core` retry policy (10 attempts, exponential backoff, honoring `Retry-After` on 429s).
- **Resilience**: a counter that fails (e.g. a service not registered in a subscription)
  contributes `0` for its fields; the rest of the row still renders.
- **AKS/serverless blind spots**: see "Known blind spots" above.
- **Cloud**: targets Azure public cloud; sovereign clouds may need endpoint overrides.

---

## Troubleshooting

- **`DefaultAzureCredential failed ... EnvironmentCredential: AADSTS700016`**
  - Stale `AZURE_*` service-principal env vars are being tried before your `az login`. Unset
    them, or make sure they point at the correct tenant/app. See the precedence gotcha above.

- **All compute counts are `0` for a subscription**
  - Either the subscription is genuinely empty, or the credential lacks **Reader** there. A
    permissions/API failure for one service is logged to stderr and reported as `0`.

- **No subscriptions found (tenant mode)**
  - The credential has no enabled subscriptions it can list; check role assignments and
    `--tenant-id`.

---

## Security Notes

- Does not write secrets to stdout/stderr.
- Files written with `--write-file` contain subscription IDs, names, and counts — store them appropriately.
