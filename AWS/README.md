# AWS Resource Counter (`uptycs_aws_counts.py`)

Count key AWS resources across a single account or every **ACTIVE** account in your AWS Organization.  
Outputs in **table**, **CSV**, or **JSON**, and can append a **JSONL** log for later analysis.

Resources counted:

- **EC2** instances (all states)
- **Lambda** functions
- **S3** buckets *(global)*
- **IAM** users & roles *(global)*
- **ECS** clusters & services

The script discovers enabled regions automatically (or you can pass your own list), assumes a role in each target account, and aggregates totals.

---

## Features

- 🔁 **Org-wide mode**: Enumerate all ACTIVE accounts via AWS Organizations.
- 👤 **Single-account mode**: Count in one account (optionally using current credentials).
- 🌍 **Region discovery**: Uses `DescribeRegions(AllRegions=True)` and filters to **enabled** regions.
- ⚙️ **Resilient calls**: Adaptive retries (botocore `adaptive` mode, max 10 attempts).
- 🧵 **Parallel per-region** scans (up to 16 workers per account).
- 🧾 **Multiple output formats**: table (pretty), CSV, JSON.
- 📝 **Structured logging**: Append a JSON line per run with `--log-file`.

> **Note on the table view:** the column widths are intentionally fixed in the code to keep alignment consistent in a plain console.

---

## Requirements

- Python **3.8+**
- Packages: `boto3` (installs `botocore`)

```bash
pip install boto3
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

**Target member account role** *(default name: `OrganizationAccountAccessRole`, override with `--assume-role-name`)*:
- Trust policy must allow the management account/role (include `ExternalId` condition if used).
- Permissions to list/describe the counted services, e.g.:
  - `ec2:DescribeInstances`
  - `lambda:ListFunctions`
  - `ecs:ListClusters`, `ecs:ListServices`
  - `s3:ListAllMyBuckets`
  - `iam:ListUsers`, `iam:ListRoles`

> Tip: AWS-managed **ReadOnlyAccess** (plus `s3:ListAllMyBuckets` if needed) is typically sufficient.  
> If you use an **ExternalId**, pass it with `--external-id`.

---

## Usage

```text
usage: uptycs_aws_counts.py --mode {org,account} [options]

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
  --log-file out.jsonl                               (append JSONL record)
```

### Built-in Examples (from the script)

```bash
# Single account using current profile
python3 uptycs_aws_counts.py --mode account --account-id 123456789012 --use-current-session --output json

# Org-wide from management (uses AWS_PROFILE or --profile)
python3 uptycs_aws_counts.py --mode org --management-account-id 123456789012 --assume-role-name OrganizationAccountAccessRole --output table

# Org-wide with a named profile
python3 uptycs_aws_counts.py --mode org --management-account-id 123456789012 --assume-role-name OrganizationAccountAccessRole --profile mgmt --output json

# Limit regions and log to file
python3 uptycs_aws_counts.py --mode account --account-id 123456789012 --regions us-east-1 us-west-2 --output csv --log-file out.jsonl
```

### More examples

```bash
# Org-wide with ExternalId and CSV output
python3 uptycs_aws_counts.py --mode org \
  --management-account-id 111122223333 \
  --assume-role-name OrgAuditRole \
  --external-id YOUR-EXTERNAL-ID \
  --output csv

# Single account using a named profile, pretty table
python3 uptycs_aws_counts.py --mode account \
  --account-id 444455556666 \
  --profile prod-admin \
  --output table
```

---

## Output

### Table (default)

A fixed-width table is printed to stdout.

```
Account ID     Name                     EC2    Lambda   S3    IAM Users  IAM Roles  ECS Clusters  ECS Services
--------------------------------------------------------------------------------------------------------------
111122223333   prod-infra               87     145      12    20         72         5             38
222233334444   sandbox                  3      12       4     2          10         1             3

TOTALS:
Accounts                 2       90       157   16   22   82   6   41
```

> If an account can’t be assumed, an error message is shown on that row and numeric fields are left blank.

### CSV

Headers:

```
account_id,account_name,ec2,lambda,s3_buckets,iam_users,iam_roles,ecs_clusters,ecs_services
```

The last row is a **TOTAL** summary.

### JSON

Structure:

```json
{
  "results": [
    {
      "account_id": "111122223333",
      "account_name": "prod-infra",
      "ec2": 87,
      "lambda": 145,
      "s3_buckets": 12,
      "iam_users": 20,
      "iam_roles": 72,
      "ecs_clusters": 5,
      "ecs_services": 38
    },
    {
      "account_id": "222233334444",
      "account_name": "sandbox",
      "ec2": 3,
      "lambda": 12,
      "s3_buckets": 4,
      "iam_users": 2,
      "iam_roles": 10,
      "ecs_clusters": 1,
      "ecs_services": 3
    }
  ],
  "totals": {
    "accounts": 2,
    "ec2": 90,
    "lambda": 157,
    "s3_buckets": 16,
    "iam_users": 22,
    "iam_roles": 82,
    "ecs_clusters": 6,
    "ecs_services": 41
  }
}
```

### Log file (`--log-file out.jsonl`)

Appends one JSON object per run, including:
- `timestamp`, `mode`, `management_account_id`, `account_id`, `profile`, `regions`, `results`, `totals`.

This is convenient for later ingestion (Athena, jq, pandas, etc.).

---

## How It Works (High Level)

1. **Target discovery**
   - **Org mode**: `ListAccounts` → ACTIVE accounts only.
   - **Account mode**: uses `--account-id`.

2. **Region list**
   - From the **base session**: `DescribeRegions(AllRegions=True)` and filtered to enabled regions (`opt-in-not-required`, `opted-in`).

3. **Assume role & count**
   - For each target account: STS `AssumeRole` (unless `--use-current-session`).
   - Global counts:
     - S3: `ListBuckets` (bucket count)
     - IAM: `ListUsers`, `ListRoles`
   - Per-region (in parallel):
     - EC2: `DescribeInstances` (instance count)
     - Lambda: `ListFunctions`
     - ECS: `ListClusters`, `ListServices`

4. **Aggregate totals** and print/output in the selected format.

---

## Performance & Limits

- **Concurrency**: up to 16 per-account regional workers.  
  For very large orgs, consider a filtered `--regions` list.
- **Throttling**: Adaptive retries are enabled (`max_attempts=10`, `mode=adaptive`).  
  Large orgs may still hit service rate limits—narrow regions or re-run.
- **Large IAM/S3**: Listing thousands of users/roles or buckets can be slow.
- **Partitions**: Targets the **commercial** AWS partition (`arn:aws:`). GovCloud/China are not supported out-of-the-box.

---

## Troubleshooting

- **`AssumeRole failed: AccessDenied`**
  - Check the target role **trust policy** (principal must include the management account/role).
  - If using `--external-id`, ensure it matches the trust policy’s `Condition`.

- **`Unable to locate credentials` / SSO expired**
  - Refresh your SSO session or set `--profile` explicitly.

- **`AccessDenied` for service list calls**
  - Ensure the **assumed role** in the member account has read/list permissions for EC2/Lambda/ECS/S3/IAM.

- **No regions found**
  - The base session must be able to call `ec2:DescribeRegions`.  
  - You can pass `--regions` explicitly.

- **S3 or IAM counts show `-1`**
  - Indicates that listing failed for that account (permissions or API error). Other services may still be counted.

- **Org mode prints “No ACTIVE accounts found”**
  - Verify Organizations is enabled and your profile points at the **management** account.

---

## Exit Codes

- `0` success (including the “no ACTIVE accounts” message)
- `2` invalid arguments or no enabled regions

---

## Security Notes

- Uses a custom user agent `aws-resource-counter/1.0`.
- Does not write secrets to stdout/stderr.
- If you enable `--log-file`, the file contains account IDs, names, and counts—store it appropriately.

---

## Quick Start

```bash
pip install boto3

# Count in your current account
python3 uptycs_aws_counts.py --mode account --account-id 123456789012 --use-current-session --output table

# Org-wide, with a management profile
AWS_PROFILE=mgmt \
python3 uptycs_aws_counts.py --mode org --management-account-id 123456789012 --output csv --log-file runs.jsonl
```

---

## License

Add a license (e.g., MIT/Apache-2.0) if you plan to distribute this tool.
