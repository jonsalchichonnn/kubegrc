from kubernetes import client, config, watch
import os
import requests
import threading
import time

# Retrieve the Slack token from environment variables
SLACK_TOKEN = os.getenv('SLACK_TOKEN')
SLACK_CHANNEL = "C08KHSY23N1" 
NAMESPACE = "osc-test"

# Notification configuration
SLACK_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
# NOTIFICATION_LIMIT = 3000  # Character limit for messages

def send_slack_notification(message):
    slack_message = {
        "channel": SLACK_CHANNEL,
        "text": message
    }
    response = requests.post(
        SLACK_MESSAGE_URL,
        headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
        json=slack_message
    )
    if response.status_code != 200:
        print(f"Failed to send notification: {response.status_code}, {response.text}")
    else:
        print("Notification sent successfully.")

# Process Kyverno PolicyReports
def process_policy_reports(event_type, report):
    name = report.get("metadata", {}).get("name", "Unknown")
    results = report.get("results", [])
    message = f"⚠️ *Kyverno Policy Report Alert*\n*Report Name:* {name}\n*Event Type:* {event_type}\n*Violations:* {len(results)}\n"
    for result in results[:5]:
        message += f"- Policy: {result['policy']} ({result['status']})\n  {result['message']}\n"
    send_slack_notification(message)

# Watch Kyverno PolicyReports
def watch_policy_reports():
    config.load_incluster_config()  # Load config once
    api = client.CustomObjectsApi()
    while True:
        try:
            watcher = watch.Watch()
            print("Watching Kyverno PolicyReports...")
            for event in watcher.stream(
                api.list_cluster_custom_object,
                group="wgpolicyk8s.io",
                version="v1alpha2",
                plural="clusterpolicyreports",
                timeout_seconds=300
            ):
                process_policy_reports(event["type"], event["object"])
        except Exception as e:
            print(f"Error watching PolicyReports: {e}")
            send_slack_notification(f"⚠️ *Error Watching PolicyReports*\nException: {str(e)}")
        finally:
            watcher.stop()  # Clean up the watcher
        time.sleep(5)  # Back off before retrying

# Watch kube-bench and kubescape CronJobs
def watch_scan_jobs(namespace="default"):
    config.load_incluster_config()  # Load config once
    api = client.BatchV1Api()
    while True:
        try:
            watcher = watch.Watch()
            print(f"Watching kube-bench and kubescape Jobs in {namespace}...")
            for event in watcher.stream(
                api.list_namespaced_job,
                namespace=namespace,
                timeout_seconds=300
            ):
                job = event["object"]
                job_name = job.metadata.name
                if "kube-bench" in job_name or "kubescape" in job_name:
                    if event["type"] == "MODIFIED":
                        if job.status.succeeded == 1:
                            send_slack_notification(f"✅ *Scan Completed: {job_name}*\nCheck the results for details.")
                        elif job.status.failed is not None and job.status.failed > 0:
                            send_slack_notification(f"❌ *Scan Failed: {job_name}*\nCheck the logs for details.")
        except Exception as e:
            print(f"Error watching Jobs: {e}")
            send_slack_notification(f"⚠️ *Error Watching Jobs*\nException: {str(e)}")
        finally:
            watcher.stop()  # Clean up the watcher
        time.sleep(5)

if __name__ == "__main__":
    policy_thread = threading.Thread(target=watch_policy_reports, daemon=True)
    job_thread = threading.Thread(target=watch_scan_jobs, args=(NAMESPACE,), daemon=True)
    
    policy_thread.start()
    job_thread.start()
    
    # Keep main thread alive
    while True:
        time.sleep(1)