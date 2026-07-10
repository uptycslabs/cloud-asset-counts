# Overview

This repository contains scripts for AWS, GCP, &amp; Azure to count the cloud assets relevant for Uptycs license cost estimation. All scripts can be run from the cloud provider's CloudShell.

# AWS

## Requirements

- Python3
- Role in each child account (same name), that has read permissions on EC2, ECS, EKS, Lambda, S3, IAM
- AWS login profile for a user that has trust policy to assume said role in each account

## Execution

- Run `python3 -m pip install -r requirements.txt` to install dependencies.
- `python3 uptycs_sizing_aws.py --mode {org,account} --management-account-id <mgmt_id> --assume-role-name <cross_account_role_name>`
- **Note:** <cross_account_role_name> is not the full ARN, it is just the last (name) part. See [AWS/README.md](AWS/README.md) for more options and examples.

## Output

- Prints a table (default), CSV, or JSON (`--output`); use `--write-file` to write CSV/JSON to a file
- Counts EC2, ECS (services, tasks & container hosts), EKS (clusters, node groups & nodes), Lambda, S3, and IAM users/roles
- The final row in the output contains the TOTALS

# Azure

## Requirements

- Python3
- `python3 -m pip install requirements.txt`

## Execution

- Login: `az login`
- Run: `python3 uptycs_azure_counts.py`

## Output

- Output is written to a file named: `uptycs_azure_counts_<tenant_id>_<date>.csv`
- Output coluns are: `subscription, region, vm_count, aks_node_count`
- The final row in the CSV output contains the TOTALS

# GCP

## Requirements

- bash (Can run from GCP CloudShell)

## Execution

- Run: `./uptycs_gcp_counts.sh`

## Output

- Output is written to a file named: `uptycs_gcp_counts_<org_id>.csv`
- Output columns are: `project, region, compute_engine_count, gke_node_count`
