# kubegrc
Evaluación de Cumplimiento y Gestión de Riesgos en Kubernetes sobre GCP

## Dependencies
### Helm
Helm is used to install and manage Kubernetes resources. Follow the [official installation guide]((https://helm.sh/docs/intro/install/)) to set it up on your system.

### Kyverno
Kyverno must be installed both in your Kubernetes cluster and locally (CLI):
- Cluster installation: [Install Kyverno in your cluster](https://kyverno.io/docs/installation/methods/#standalone-installation).
- Local CLI: [Install the Kyverno CLI](https://kyverno.io/docs/installation/methods/#standalone-installation) to enable local policy testing and validation.

### OpenKruise
OpenKruise extends Kubernetes workload capabilities. Please install it by following the [official installation instructions](https://openkruise.io/docs/installation/#install-with-helm).

## Prerequisites
### Setting up environment variables
Before deploying, create the environment variable SLACK_TOKEN for alert communications.

### Setting up GCP credentials
1. Create the GCP service account and grant bucket permissions:

    ```bash
    # Create a service account
    gcloud iam service-accounts create kubegrc-bucket-sa \
        --display-name="Kubegrc Bucket Service Account"

    # Grant storage access to the service account
    gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
        --member="serviceAccount:kubegrc-bucket-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
        --role="roles/storage.objectViewer"

    gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
        --member="serviceAccount:kubegrc-bucket-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
        --role="roles/storage.objectCreator"
    ```

2. Create and download the service account key:
    ```bash
    # Create and download the key
    gcloud iam service-accounts keys create gcp-credentials.json \
        --iam-account=kubegrc-bucket-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
    ```

### ⚠️ Security Warning: Protecting GCP Credentials
The `gcp-credentials.json` file contains sensitive information that grants access to your GCP resources. Follow these security best practices:

1. **Never commit** the credentials file to version control
2. **Immediately delete** the local credentials file after creating the Kubernetes secret
3. **Restrict access** to the Kubernetes secret to only necessary personnel
4. **Rotate credentials** periodically by creating new keys and updating the secret
5. **Use minimal permissions** - only grant the necessary roles to the service account
6. **Monitor usage** of the service account for any suspicious activity

To add the credentials file to .gitignore:
```bash
echo "gcp-credentials.json" >> .gitignore
```

To verify the file is not tracked by git:
```bash
git check-ignore gcp-credentials.json
```