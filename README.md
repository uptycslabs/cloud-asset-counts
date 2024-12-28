# Overview
This repository contains scripts for AWS, GCP, &amp; Azure to count the cloud assets relevant for Uptycs license cost estimation. All scripts can be run from the cloud provider's CloudShell.

# AWS
## Requirements
  * Python3
  * `python3 -m pip install requirements.txt`
  * Role in each child account (same name), that has read permissions on EC2, Lambda
  * AWS login profile for a user that has trust policy to assume said role in each account
  
## Execution
  `python3 uptycs_aws_counts.py <aws_profile> <cross_account_role_name>`  
Note <cross_account_role_name> is not the full ARN, it is just the last (name) part
## Output
  * Output is written to a file named: `uptycs_aws_counts_<org_id>_<date>.csv`
  * Output coluns are: `account, region, ec2_node_count, lambda_function_count`
  * EKS nodes are included in the `ec2_node_count` column
  * The final row in the CSV output contains the TOTALS   
  
# Azure
## Requirements
  * Python3
  * `python3 -m pip install requirements.txt` 
  
## Execution
* Login: `az login`
* Run: `python3 uptycs_azure_counts.py`  

## Output
  * Output is written to a file named: `uptycs_azure_counts_<tenant_id>_<date>.csv`
  * Output coluns are: `subscription, region, vm_count, aks_node_count` 
  * The final row in the CSV output contains the TOTALS  

# GCP
## Requirements
  * bash (Can run from GCP CloudShell)
  
## Execution
* Run: `./uptycs_gcp_counts.sh`  

## Output
  * Output is written to a file named: `uptycs_gcp_counts_<org_id>.csv`
  * Output columns are: `project, region, compute_engine_count, gke_node_count` 


