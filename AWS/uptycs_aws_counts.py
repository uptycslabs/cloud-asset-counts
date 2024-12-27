import boto3
import csv
import sys
from datetime import datetime
from botocore.exceptions import ClientError

# Constants
OUTPUT_FILENAME_TEMPLATE = "uptycs_aws_counts_{org_id}_{date}.csv"
HEADER = ["account", "region", "ec2_nodes", "lambda_count"]

def assume_role(profile_name, account_id, role_name):
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client("sts")
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="ResourceCounterSession"
        )
        credentials = assumed_role["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
    except ClientError as e:
        print(f"Error assuming role for account {account_id}: {e}")
        return None


def get_org_id(profile_name):
    try:
        session = boto3.Session(profile_name=profile_name)
        org_client = session.client("organizations")
        response = org_client.describe_organization()
        return response["Organization"]["Id"]
    except ClientError as e:
        print(f"Error retrieving organization ID: {e}")
        sys.exit(1)


def get_all_regions(session):
    ec2_client = session.client("ec2", region_name="us-east-1")
    try:
        regions = ec2_client.describe_regions()["Regions"]
        return [region["RegionName"] for region in regions]
    except ClientError as e:
        print(f"Error retrieving regions: {e}")
        return []


def count_resources_in_region(session, region):
    ec2_nodes = lambda_count = 0

    # Count EC2 nodes
    try:
        ec2_client = session.client("ec2", region_name=region)
        ec2_nodes = sum(1 for _ in ec2_client.describe_instances()["Reservations"])
    except ClientError as e:
        print(f"Error counting EC2 instances in {region}: {e}")

    # Count Lambda functions
    try:
        lambda_client = session.client("lambda", region_name=region)
        functions = lambda_client.list_functions()["Functions"]
        lambda_count = len(functions)
    except ClientError as e:
        print(f"Error counting Lambda functions in {region}: {e}")

    return ec2_nodes, lambda_count


def main(profile_name, role_name):
    # Get organization ID
    org_id = get_org_id(profile_name)

    # Initialize the output CSV file
    the_date = datetime.now().strftime("%Y-%m-%d")
    output_file = OUTPUT_FILENAME_TEMPLATE.format(org_id=org_id, date=the_date)
    
    with open(output_file, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(HEADER)

        # List accounts in the organization
        session = boto3.Session(profile_name=profile_name)
        org_client = session.client("organizations")
        try:
            accounts = org_client.list_accounts()["Accounts"]
        except ClientError as e:
            print(f"Error listing accounts: {e}")
            sys.exit(1)

        total_ec2_nodes = total_lambda_count = 0

        for account in accounts:
            account_id = account["Id"]
            session = assume_role(profile_name, account_id, role_name)
            if not session:
                continue

            regions = get_all_regions(session)

            for region in regions:
                ec2_nodes, lambda_count = count_resources_in_region(session, region)

                # Only write rows where at least one count > 0
                if ec2_nodes > 0 or lambda_count > 0:
                    writer.writerow([account_id, region, ec2_nodes, lambda_count])

                total_ec2_nodes += ec2_nodes
                total_lambda_count += lambda_count

        # Write totals
        writer.writerow(["TOTAL", "ALL", total_ec2_nodes, total_lambda_count])

    print(f"Resource counts written to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <aws_profile_name> <cross_account_role_name>")
        sys.exit(1)

    profile_name = sys.argv[1]
    role_name = sys.argv[2]

    main(profile_name, role_name)


