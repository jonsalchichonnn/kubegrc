#!/bin/bash
set -u # Treats unset variables as an error and exit
set -o pipefail # exit if pipe error
#set -x # print command before execution (debug)

echo "[+] Checking current environment resources compliance..."
# Save policy report to a file with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
POLICY_REPORT_FILE="kyverno_policy_report_${TIMESTAMP}.yaml"
kubectl kyverno apply pss.yaml --cluster --policy-report > ${POLICY_REPORT_FILE}
set -e  # enable error exit now because initial scan exit value is always > 0

echo "[+] Configuring dependencies for kubegrc..."
kubectl apply -f create-namespace.yaml
echo "[+] Created namespace for kubegrc!"

# Upload initial scan report to GCS bucket
kubectl delete secret gcp-bucket-credentials -n osc-test --ignore-not-found
kubectl create secret generic gcp-bucket-credentials --from-file=credentials.json=gcp-credentials.json -n osc-test
gsutil cp ${POLICY_REPORT_FILE} gs://kubegrc/scan-results/kyverno/
rm ${POLICY_REPORT_FILE}  # Clean up local file

kubectl delete secret slack-secret -n osc-test --ignore-not-found
kubectl create secret generic slack-secret --from-literal=SLACK_TOKEN=$SLACK_TOKEN -n osc-test

# kubenbench set up
kubectl apply -f kubebench-acj.yaml
echo "[+] kube-bench scans scheduled!"

# kubescape set up
kubectl apply -f kubescape-sa.yaml
kubectl apply -f kubescape-cj.yaml
echo "[+] kubescape scans scheduled!"

kubectl apply -f event-alert-sa.yaml
kubectl apply -f event-monitor-deploy.yaml
echo "[+] Monitoring configured"

# kyverno policies enforcement 
kubectl apply -f pss-namespace-policies.yaml
echo "[+] Security policies applied!"
echo "[+] KubeGRC is up and running!!!"