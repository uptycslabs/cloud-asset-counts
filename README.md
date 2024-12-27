<h1>Overview</h1>
This repository contains scripts for AWS, GCP, &amp; Azure to count the cloud assets relevant for Uptycs license cost estimation. 

<h1>AWS</h1>
<h2>Requirements</h2>
  - Python3
  - ```python3 -m pip install requirements.txt``` 
  
<h2>Execution</h2>
  ```python3 uptycs_aws_counts.py <aws_profile> <cross_account_role_name>```
Note the <cross_account_role_name> argument is not the full ARN, it is just the last name part
<h2>Output</h2>
  - Output is written to uptycs_aws_counts_<org_id>_<date>.csv
  - Output coluns are: account, region, ec2_nodes, lambda_functions
  - EKS nodes are included in the ec2_nodes column
  - The final row contains the TOTALS   
  
<h1>Azure</h1>

<h1>GCP</h1>
