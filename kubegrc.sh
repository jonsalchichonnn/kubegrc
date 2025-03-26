#!/bin/bash
set -e # exit if error
set -u # Treats unset variables as an error and exit
set -o pipefail # exit if pipe error
set -x # print command before execution (debug)

kubectl apply -f create-namespace.yaml

# kubenbench set up
kubectl apply -f kubebench-acj.yaml

# kubescape set up
kubectl apply -f kubescape-sa.yaml
kubectl apply -f kubescape-cj.yaml

# kyverno policies enforcement + default initial scan
kubectl kyverno apply pss.yaml --cluster - &