#!/bin/bash

# Output CSV file
OUTPUT_FILE="gcp_resource_counts.csv"

# Write CSV header
echo "project_id,region,vm_count,gke_node_count" > $OUTPUT_FILE

# Get a list of all projects
PROJECTS=$(gcloud projects list --format="value(projectId)")

# Iterate through each project
for PROJECT in $PROJECTS; do
    echo "Processing project: $PROJECT"
    
    # Set the project for gcloud commands
    gcloud config set project $PROJECT > /dev/null 2>&1

    # Get all regions for the project
    REGIONS=$(gcloud compute regions list --format="value(name)")

    # Iterate through each region
    for REGION in $REGIONS; do
        # Count the Compute Engine instances in the region
        VM_COUNT=$(gcloud compute instances list \
            --filter="zone:($REGION)" \
            --format="csv[no-heading](name)" | wc -l)

        # Count the GKE nodes in the region
        GKE_NODE_COUNT=$(gcloud container clusters list \
            --filter="location:($REGION)" \
            --format="value(name)" | while read CLUSTER; do
                if [[ -n $CLUSTER ]]; then
                    gcloud container node-pools list \
                        --cluster=$CLUSTER \
                        --region=$REGION \
                        --format="csv[no-heading](name)" | wc -l
                fi
            done | awk '{s+=$1} END {print s+0}')

        # Write the data to the CSV
        echo "$PROJECT,$REGION,$VM_COUNT,$GKE_NODE_COUNT" >> $OUTPUT_FILE
    done
done

echo "Resource counts have been written to $OUTPUT_FILE"


