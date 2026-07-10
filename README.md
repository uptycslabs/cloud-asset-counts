# Overview

This repository contains scripts for AWS, GCP, &amp; Azure to count the cloud assets relevant for Uptycs license cost estimation. All scripts can be run from the cloud provider's CloudShell.

# AWS

## Requirements

- Python3
- `python3 -m pip install -r requirements.txt`
- Role in each child account (same name), that has read permissions on EC2, ECS, EKS, Lambda, S3, IAM
- AWS login profile for a user that has trust policy to assume said role in each account

## Execution

`python3 uptycs_sizing_aws.py --mode {org,account} --management-account-id <mgmt_id> --assume-role-name <cross_account_role_name>`
Note <cross_account_role_name> is not the full ARN, it is just the last (name) part. See [AWS/README.md](AWS/README.md) for more options and examples.

## Output

- Prints a table (default), CSV, or JSON (`--output`); use `--write-file` to write CSV/JSON to a file
- Counts EC2, ECS (services, tasks & container hosts), EKS (clusters, node groups & nodes), Lambda, S3, and IAM users/roles
- The final row in the output contains the TOTALS

# Azure

## Requirements

- Python3 (3.8+)
- `python3 -m pip install -r requirements.txt`
- **Reader** role on each target subscription; for Entra ID counts, Microsoft Graph `User.Read.All` + `Directory.Read.All`
- Azure login: `az login`, or a service principal via `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`

## Execution

`python3 uptycs_sizing_azure.py --mode {subscription,tenant} [--subscription-id <id>]`
See [Azure/README.md](Azure/README.md) for more options and examples.

## Output

- Prints a table (default), CSV, or JSON (`--output`); use `--write-file` to write CSV/JSON to a file
- Counts Virtual Machines, VM Scale Sets (& instances), AKS (clusters, node pools & nodes), Azure Container Instances (groups & containers), App Service (Functions & Web Apps), Container Apps (& environments), and Entra ID users/roles
- The final row in the output contains the TOTALS

# GCP

## Requirements

- bash (Can run from GCP CloudShell)

## Execution

- Run: `./uptycs_gcp_counts.sh`

## Output

- Output is written to a file named: `uptycs_gcp_counts_<org_id>.csv`
- Output columns are: `project, region, compute_engine_count, gke_node_count`
