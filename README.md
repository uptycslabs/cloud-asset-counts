# Overview
This repository contains scripts for AWS, GCP, &amp; Azure to count the cloud assets relevant for Uptycs license cost estimation. 

# AWS
## Requirements
  * Python3
  * `python3 -m pip install requirements.txt` 
  
# Execution
  `python3 uptycs_aws_counts.py <aws_profile> <cross_account_role_name>`
Note <cross_account_role_name> is not the full ARN, it is just the last (name) part
## Output
  * Output is written to uptycs_aws_counts_<org_id>_<date>.csv
  * Output coluns are: account, region, ec2_nodes, lambda_functions
  * EKS nodes are included in the ec2_nodes column
  * The final row contains the TOTALS   
  
# Azure

# GCP
