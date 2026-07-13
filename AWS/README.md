# AWS Resource Counter (`uptycs_sizing_aws.py`)

Count key AWS resources across a single account or every **ACTIVE** account in your AWS Organization.
Outputs in **table**, **CSV**, or **JSON** (to stdout or to a file).

Resources counted:

- **EC2** instances — running and stopped (terminated/shutting-down are excluded)
- **ECS** — clusters, services, and running tasks, each split into **Fargate** (serverless) and **EC2** (your own instances), plus **container hosts** (machines registered to run ECS tasks)
- **EKS** — clusters, node groups, and worker **nodes** (including nodes managed by EKS Auto Mode)
- **Lambda** functions
- **S3** buckets _(global)_
- **IAM** users & roles _(global)_

The script discovers enabled regions automatically (or you can pass your own list), assumes a role in each target account, and aggregates totals.

### Counted once, never twice

A single machine can serve more than one purpose, so the script takes care not to double-count it:

- A machine registered as an **ECS container instance** is reported under `ECS-Container-Instances` and removed from the `EC2-Standalone` count.
- A machine acting as an **EKS worker node** is reported under `EKS-Nodes` and removed from the `EC2-Standalone` count.
- Machines that are **not** EC2 instances — on-premises ECS Anywhere hosts, or the nodes EKS Auto Mode runs for you — are counted **in addition** to your EC2 total, since they are genuinely separate machines. ECS Anywhere hosts that turn out to be EC2 instances are matched back by IP and counted only once.

---

## Features

- 🔁 **Org-wide mode**: Enumerate all ACTIVE accounts via AWS Organizations.
- 👤 **Single-account mode**: Count in one account (optionally using current credentials).
- 🌍 **Region discovery**: Uses `DescribeRegions(AllRegions=True)` and filters to **enabled** regions.
- 🧮 **De-duplicated compute counts**: container hosts and EKS nodes are not double-counted as EC2.
- ⚙️ **Resilient calls**: Adaptive retries (botocore `adaptive` mode, max 10 attempts).
- 🧵 **Parallel per-region** scans (up to 16 workers per account).
- 🧾 **Multiple output formats**: table (pretty), CSV, JSON — printed to stdout or written to a file.

> **Note on the table view:** the column widths are intentionally fixed in the code to keep alignment consistent in a plain console.

---

## Requirements

- Python **3.10+**
- Packages: `boto3` (installs `botocore`)
- **boto3/botocore 1.42.94+**

Dependencies are pinned in [`requirements.txt`](requirements.txt):

```text
boto3>=1.42.94
```

Install them with either:

```bash
# From requirements.txt
pip install -r requirements.txt

# Or directly
pip install "boto3>=1.42.94"
```

---

## Setup & Authentication

Run with either:

- your current AWS credentials (for a single account), or
- a **management** (payer) account/profile that can call AWS Organizations and **assume** a role in each member account.

### IAM requirements

**Management (caller) account** permissions:

- `organizations:ListAccounts`
- `sts:AssumeRole` (to the target role ARN in each member account)

**Target member account role** _(default name: `OrganizationAccountAccessRole`, override with `--assume-role-name`)_:

- Trust policy must allow the management account/role (include an `ExternalId` condition if used).
- Permissions to list/describe the counted services, e.g.:
  - `ec2:DescribeInstances`, `ec2:DescribeRegions`
  - `lambda:ListFunctions`
  - `ecs:ListClusters`, `ecs:ListServices`, `ecs:DescribeServices`, `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:ListContainerInstances`, `ecs:DescribeContainerInstances`, `ecs:DescribeCapacityProviders`
  - `ssm:DescribeInstanceInformation` (to reconcile ECS Anywhere hosts with EC2)
  - `eks:ListClusters`, `eks:ListNodegroups`
  - `s3:ListAllMyBuckets`
  - `iam:ListUsers`, `iam:ListRoles`, `iam:ListAccountAliases` (account name in account mode)

> Tip: AWS-managed **ReadOnlyAccess** is typically sufficient.
> If you use an **ExternalId**, pass it with `--external-id`.

---

## Usage

```text
usage: uptycs_sizing_aws.py --mode {org,account} [options]

Required (choose a mode):
  --mode org --management-account-id <ID>
  --mode account --account-id <ID>

Common options:
  --assume-role-name OrganizationAccountAccessRole   (default)
  --external-id <string>                             (optional)
  --regions us-east-1 us-west-2 ...                  (optional; default: all enabled)
  --output {table,json,csv}                          (default: table)
  --use-current-session                              (single-account with current creds)
  --profile <name>                                   (overrides AWS_PROFILE)
  --write-file [PATH]                                (json/csv only; auto-names if PATH omitted)
```

### Examples

#### Single account

```bash
# Scan a specific account with your current credentials (no role assumed)
python3 uptycs_sizing_aws.py --mode account \
  --account-id 123456789012 \
  --use-current-session \
  --output json

# Scan another account by assuming a role into it
python3 uptycs_sizing_aws.py --mode account \
  --account-id 222233334444 \
  --assume-role-name OrganizationAccountAccessRole \
  --output table

# Assume a role that requires an ExternalId
python3 uptycs_sizing_aws.py --mode account \
  --account-id 222233334444 \
  --assume-role-name UptycsSizingRole \
  --external-id my-external-id \
  --output json
```

#### Organization-wide

Run with management-account or delegated-admin credentials (e.g. via `--profile`).

```bash
# Org-wide from management
python3 uptycs_sizing_aws.py --mode org \
  --management-account-id 123456789012 \
  --assume-role-name OrganizationAccountAccessRole \
  --output table

# Org-wide with a named profile
python3 uptycs_sizing_aws.py --mode org \
  --management-account-id 123456789012 \
  --assume-role-name OrganizationAccountAccessRole \
  --profile mgmt \
  --output json

# Org-wide where the member-account roles require an ExternalId
python3 uptycs_sizing_aws.py --mode org \
  --management-account-id 123456789012 \
  --assume-role-name UptycsSizingRole \
  --external-id my-external-id \
  --output json
```

#### More examples — running with `uv` (no venv needed)

[`uv`](https://docs.astral.sh/uv/) can run the script in one shot with the required dependency pinned, without creating or activating a virtual environment.

**Requirements:**

- `uv` installed. If you don't have it:
  ```bash
  # macOS / Linux
  curl -LsSf https://astral.sh/uv/install.sh | sh

  # or via pip
  pip install uv
  ```
- `uv` provides Python automatically, so no separate Python install is required.
- Valid AWS credentials in your environment (env vars, `--profile`, or an assumable role), same as any other run.

```bash
# Run in one shot with the dependency pinned, without activating a venv
uv run --with "boto3>=1.42.94" python3 uptycs_sizing_aws.py --mode account \
  --account-id 123456789012 \
  --use-current-session \
  --output json
```

---

## Output

The same set of columns drives the table and CSV, so they always match:

| Column                  | Key                       | Meaning                                                   |
| ----------------------- | ------------------------- | -------------------------------------------------------- |
| Account ID              | `account_id`              | Target account                                           |
| Name                    | `account_name`            | Account name (org mode)                                  |
| EC2-Standalone          | `ec2_standalone`          | EC2 instances, excluding container instances and EKS nodes |
| ECS-Clusters            | `ecs_clusters`            | ECS clusters                                             |
| ECS-Services-Total      | `ecs_services_total`      | ECS services (EC2 + Fargate)                             |
| ECS-Services-EC2        | `ecs_services_ec2`        | ECS services running on EC2                              |
| ECS-Services-Fargate    | `ecs_services_fargate`    | ECS services running on Fargate                          |
| ECS-Tasks-EC2           | `ecs_tasks_ec2`           | Running EC2-backed tasks                                 |
| ECS-Tasks-Fargate       | `ecs_tasks_fargate`       | Running Fargate tasks                                    |
| ECS-Container-Instances | `ecs_container_instances` | EC2 instances registered to run ECS tasks               |
| EKS-Clusters            | `eks_clusters`            | EKS clusters                                             |
| EKS-NodeGroups          | `eks_nodegroups`          | EKS node groups                                          |
| EKS-Nodes               | `eks_nodes`               | EKS worker nodes (incl. Auto Mode)                       |
| Lambda-Functions        | `lambda_functions`        | Lambda functions                                         |
| S3-Buckets              | `s3_buckets`              | S3 buckets                                               |
| IAM-Users               | `iam_users`               | IAM users                                                |
| IAM-Roles               | `iam_roles`               | IAM roles                                                |

### Table (default)

A fixed-width table is printed to stdout, with a `TOTALS` line and a scan-timing footer (UTC start/end) at the end. It is wide (17 columns), so the raw console output wraps in a narrow terminal. The same data is shown below as a table for readability:

| Account ID   | Name       | EC2-Standalone | ECS-Clusters | ECS-Services-Total | ECS-Services-EC2 | ECS-Services-Fargate | ECS-Tasks-EC2 | ECS-Tasks-Fargate | ECS-Container-Instances | EKS-Clusters | EKS-NodeGroups | EKS-Nodes | Lambda-Functions | S3-Buckets | IAM-Users | IAM-Roles |
| ------------ | ---------- | -------------- | ------------ | ------------------ | ---------------- | -------------------- | ------------- | ----------------- | ----------------------- | ------------ | -------------- | --------- | ---------------- | ---------- | --------- | --------- |
| 111122223333 | prod-infra | 87             | 5            | 38                 | 30               | 8                    | 60            | 14                | 6                       | 2            | 4              | 12        | 145              | 12         | 20        | 72        |
| 222233334444 | sandbox    | 3              | 1            | 3                  | 3                | 0                    | 5             | 0                 | 0                       | 0            | 0              | 0         | 12               | 4          | 2         | 10        |
| **TOTALS**   |            | 90             | 6            | 41                 | 33               | 8                    | 65            | 14                | 6                       | 2            | 4              | 12        | 157              | 16         | 22        | 82        |

> If an account can’t be assumed, the row shows zeros and an `error` note explaining why, so one account never hides the rest of the report.

The footer reports when the scan started and ended (UTC):

```
Scan started: 2026-07-13T09:00:01Z
Scan ended:   2026-07-13T09:02:14Z
```

### CSV

The header row matches the columns above; then one row per account, a **TOTALS** summary row, and two trailing scan-timing rows (`Scan started`, `Scan ended`). Use `--write-file [PATH]` to write to a file instead of stdout.

```csv
Account ID,Name,EC2-Standalone,...
111122223333,prod-infra,87,...
TOTALS,,90,...
Scan started,2026-07-13T09:00:01Z
Scan ended,2026-07-13T09:02:14Z
```

### JSON

Structure (`scan` holds run timing; `results` is one object per account; `totals` aggregates all counted fields):

```json
{
  "scan": {
    "started_at": "2026-07-13T09:00:01Z",
    "ended_at": "2026-07-13T09:02:14Z"
  },
  "results": [
    {
      "account_id": "111122223333",
      "account_name": "prod-infra",
      "ec2_standalone": 87,
      "ecs_clusters": 5,
      "ecs_services_total": 38,
      "ecs_services_ec2": 30,
      "ecs_services_fargate": 8,
      "ecs_tasks_ec2": 60,
      "ecs_tasks_fargate": 14,
      "ecs_container_instances": 6,
      "eks_clusters": 2,
      "eks_nodegroups": 4,
      "eks_nodes": 12,
      "lambda_functions": 145,
      "s3_buckets": 12,
      "iam_users": 20,
      "iam_roles": 72
    }
  ],
  "totals": {
    "ec2_standalone": 87,
    "ecs_clusters": 5,
    "ecs_services_total": 38,
    "ecs_services_ec2": 30,
    "ecs_services_fargate": 8,
    "ecs_tasks_ec2": 60,
    "ecs_tasks_fargate": 14,
    "ecs_container_instances": 6,
    "eks_clusters": 2,
    "eks_nodegroups": 4,
    "eks_nodes": 12,
    "lambda_functions": 145,
    "s3_buckets": 12,
    "iam_users": 20,
    "iam_roles": 72
  }
}
```

Use `--write-file [PATH]` to save the JSON to a file. With no path, the file is auto-named `uptycs_sizing_<scope>_<timestamp>.json`.

---

## How It Works (High Level)

1. **Target discovery**
   - **Org mode**: `ListAccounts` → ACTIVE accounts only.
   - **Account mode**: uses `--account-id` (or the caller's account).

2. **Region list**
   - From the **base session**: `DescribeRegions(AllRegions=True)`, filtered to enabled regions (`opt-in-not-required`, `opted-in`). Skipped when `--regions` is given.

3. **Assume role & count**
   - For each target account: STS `AssumeRole` (unless `--use-current-session`, or the target is the caller's own account).
   - Account-wide counts:
     - S3: `ListBuckets`
     - IAM: `ListUsers`, `ListRoles`
   - Per-region (in parallel):
     - EC2: `DescribeInstances`
     - Lambda: `ListFunctions`
     - ECS: clusters, services, tasks, and container instances (reconciled against EC2/SSM)
     - EKS: clusters, node groups, and worker nodes (incl. Auto Mode)
   - Container instances and EKS nodes are subtracted from the EC2-Standalone count so no machine is counted twice.

4. **Aggregate totals** and print/output in the selected format.

---

## Performance & Limits

- **Concurrency**: up to 16 per-account regional workers.
  For very large orgs, consider a filtered `--regions` list.
- **Throttling**: Adaptive retries are enabled (`max_attempts=10`, `mode=adaptive`).
  Large orgs may still hit service rate limits — narrow regions or re-run.
- **Large IAM/S3**: Listing thousands of users/roles or buckets can be slow.
- **Partitions**: Targets the **commercial** AWS partition (`arn:aws:`). GovCloud/China are not supported out-of-the-box.

---

## Troubleshooting

- **`AssumeRole failed: AccessDenied`**
  - Check the target role **trust policy** (principal must include the management account/role).
  - If using `--external-id`, ensure it matches the trust policy’s `Condition`.

- **`Unable to locate credentials` / SSO expired**
  - Refresh your SSO session or set `--profile` explicitly.

- **`NOTE: ... EKS Auto Mode nodes not counted`**
  - Your boto3/botocore is older than 1.42.94. Upgrade to include Auto Mode nodes.

- **`WARNING: ... could not reconcile ECS Anywhere hosts with EC2`**
  - `ssm:DescribeInstanceInformation` is missing; some hosts may be double-counted as both EC2 and container hosts.

- **S3 or IAM counts show `-1`**
  - Listing failed for that account (permissions or API error). Other services may still be counted.

- **No regions found**
  - The base session must be able to call `ec2:DescribeRegions`, or pass `--regions` explicitly.

---

## Security Notes

- Uses a custom user agent `aws-resource-counter/1.0`.
- Does not write secrets to stdout/stderr.
- Files written with `--write-file` contain account IDs, names, and counts — store them appropriately.

---

## Quick Start

```bash
pip install "boto3>=1.42.94"

# Count in your current account
python3 uptycs_sizing_aws.py --mode account \
  --account-id 123456789012 \
  --use-current-session \
  --output table

# Org-wide, with a management profile
python3 uptycs_sizing_aws.py --mode org \
  --management-account-id 123456789012 \
  --profile mgmt \
  --output csv \
  --write-file sizing.csv
```

---

## License

Add a license (e.g., MIT/Apache-2.0) if you plan to distribute this tool.
