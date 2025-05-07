#!/bin/bash
set -e # exit if error
set -u # Treats unset variables as an error and exit
set -o pipefail # exit if pipe error
set -x # print command before execution (debug)

kubectl apply -f create-namespace.yaml

kubectl delete secret slack-secret -n osc-test --ignore-not-found
kubectl create secret generic slack-secret --from-literal=SLACK_TOKEN=$SLACK_TOKEN -n osc-test

# kubenbench set up
kubectl apply -f kubebench-acj.yaml

# kubescape set up
kubectl apply -f kubescape-sa.yaml
kubectl apply -f kubescape-cj.yaml


kubectl apply -f event-alert-sa.yaml
kubectl apply -f event-monitor-deploy.yaml

# kyverno policies enforcement + default initial scan
kubectl kyverno apply pss.yaml --cluster --policy-report 
kubectl apply -f pss.yaml # TODO: ADD EXECEPTIONS FOR SCRIPT DEPENDENCIES