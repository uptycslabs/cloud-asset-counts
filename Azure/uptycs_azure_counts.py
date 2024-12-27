from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from concurrent.futures import ThreadPoolExecutor
import logging
from typing import Dict, List, Tuple
import csv
from datetime import datetime
import re
import subprocess
import os
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AzureResourceCounter:
    def __init__(self):
        self.credential = DefaultAzureCredential()
        self.subscription_client = SubscriptionClient(self.credential)
        self.tenant_id = self._get_tenant_id()

    def _get_tenant_id(self) -> str:
        """Get the tenant ID."""
        try:
            tenant_id = ""
            pattern = "tenantId"
            az_result = subprocess.run(["az", "account", "list"], stdout=subprocess.PIPE, text=True)
            az_output = az_result.stdout.strip()
            for line in az_output.split('\n'):
                if pattern in line:
                    tenant_id = str(re.search(r'"tenantId":\s*"([^"]+)"', line).group(1))
                    print("TenantId: "+tenant_id)
                    return tenant_id
        except Exception as e:
            logger.error(f"Error getting tenant ID: {str(e)}")
            return "unknown-tenant"

    def get_subscriptions(self) -> List[str]:
        """Get all enabled subscription IDs."""
        try:
            return [sub.subscription_id for sub in self.subscription_client.subscriptions.list()
                    if sub.state == "Enabled"]
        except Exception as e:
            logger.error(f"Error getting subscriptions: {str(e)}")
            raise

    def count_vms_by_region(self, subscription_id: str) -> List[Tuple[str, str, int]]:
        """Count VMs in each region for a subscription."""
        try:
            compute_client = ComputeManagementClient(self.credential, subscription_id)
            vm_counts = {}
            
            for vm in compute_client.virtual_machines.list_all():
                region = vm.location.lower()  # Normalize region names
                vm_counts[region] = vm_counts.get(region, 0) + 1
                
            return [(subscription_id, region, count) for region, count in vm_counts.items()]
        except Exception as e:
            logger.error(f"Error counting VMs in subscription {subscription_id}: {str(e)}")
            return [(subscription_id, "error", 0)]

    def count_aks_nodes_by_region(self, subscription_id: str) -> List[Tuple[str, str, int]]:
        """Count AKS nodes in each region for a subscription."""
        try:
            aks_client = ContainerServiceClient(self.credential, subscription_id)
            node_counts = {}
            
            for cluster in aks_client.managed_clusters.list():
                region = cluster.location.lower()  # Normalize region names
                if cluster.agent_pool_profiles:
                    for pool in cluster.agent_pool_profiles:
                        if pool.enable_auto_scaling:
                            node_counts[region] = node_counts.get(region, 0) + pool.max_count
                        else:
                            node_counts[region] = node_counts.get(region, 0) + pool.count
                            
            return [(subscription_id, region, count) for region, count in node_counts.items()]
        except Exception as e:
            logger.error(f"Error counting AKS nodes in subscription {subscription_id}: {str(e)}")
            return [(subscription_id, "error", 0)]

    def get_resource_counts(self) -> List[Dict]:
        """Get counts of VMs and AKS nodes across all subscriptions and regions."""
        subscriptions = self.get_subscriptions()
        results = []
        print(f"Processing {len(subscriptions)} subscriptions...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            # Count VMs and AKS nodes in parallel
            vm_futures = {executor.submit(self.count_vms_by_region, sub): sub 
                         for sub in subscriptions}
            aks_futures = {executor.submit(self.count_aks_nodes_by_region, sub): sub 
                          for sub in subscriptions}

            # Process results
            resource_map = {}
            
            # Process VM results
            for future in vm_futures:
                for sub_id, region, count in future.result():
                    key = (sub_id, region)
                    if key not in resource_map:
                        resource_map[key] = {
                            "subscription": sub_id,
                            "region": region,
                            "vm_count": 0,
                            "aks_node_count": 0
                        }
                    resource_map[key]["vm_count"] = count

            # Process AKS results
            for future in aks_futures:
                for sub_id, region, count in future.result():
                    key = (sub_id, region)
                    if key not in resource_map:
                        resource_map[key] = {
                            "subscription": sub_id,
                            "region": region,
                            "vm_count": 0,
                            "aks_node_count": 0
                        }
                    resource_map[key]["aks_node_count"] = count

        return list(resource_map.values())

    def write_results_to_csv(self, results: List[Dict]):
        """Write results to CSV file including totals."""
        #timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        timestamp = datetime.now().strftime("%Y-%m-%d")
        filename = f"uptycs_azure_counts_{self.tenant_id}_{timestamp}.csv"
        
        # Calculate totals
        total_vms = sum(row['vm_count'] for row in results)
        total_aks = sum(row['aks_node_count'] for row in results)
        
        # Sort results by subscription and region
        sorted_results = sorted(results, key=lambda x: (x['subscription'], x['region']))
        
        # Write to CSV
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['subscription', 'region', 'vm_count', 'aks_node_count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            # Write all results
            for row in sorted_results:
                writer.writerow(row)
            
            # Write total row
            writer.writerow({
                'subscription': 'TOTALS',
                'region': 'ALL_REGIONS',
                'vm_count': total_vms,
                'aks_node_count': total_aks
            })
        
        return filename, total_vms, total_aks

def main():
    # Redirect stdout to devnull temporarily to suppress Azure SDK headers
    stdout = sys.stdout
    sys.stdout = open(os.devnull, 'w')

    counter = AzureResourceCounter()
    try:
        results = counter.get_resource_counts()
        filename, total_vms, total_aks = counter.write_results_to_csv(results)
        
        # Restore stdout for our own output
        sys.stdout = stdout
        print(f"\nResults written to: {filename}")
        print(f"Total VMs: {total_vms}")
        print(f"Total AKS nodes: {total_aks}")
        
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        raise

if __name__ == "__main__":
    main()
