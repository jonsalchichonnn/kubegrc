from kubernetes import client, config, watch
import os
import requests
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone


# Retrieve the Slack token from environment variables
SLACK_TOKEN = os.getenv('SLACK_TOKEN')
if not SLACK_TOKEN:
    raise ValueError("SLACK_TOKEN environment variable is not set")

SLACK_CHANNEL = "C08KHSY23N1"
NAMESPACE = "osc-test"

# Notification configuration
SLACK_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
RETRIES = 3
DELAY = 5
CACHE_MAX_SIZE = 10
TIMEOUT = 6
notified_jobs = OrderedDict()


def add_to_cache(job_name):
    # Add the job to the cache with the current timestamp
    notified_jobs[job_name] = time.time()

    # If the cache exceeds the max size, remove the oldest item
    if len(notified_jobs) > CACHE_MAX_SIZE:
        notified_jobs.popitem(last=False)


def is_job_notified(job_name):
    # Check if the job is already in the cache
    return job_name in notified_jobs


def send_slack_notification(message):
    for attempt in range(RETRIES):
        response = requests.post(
            SLACK_MESSAGE_URL,
            headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
            json={"channel": SLACK_CHANNEL, "text": message}
        )
        if response.status_code == 200:
            print("Notification sent successfully.")
            return
        print(
            f"Failed to send notification: {response.status_code}, {response.text}")
        time.sleep(DELAY)
    print("Failed to send notification after retries.")


def watch_policy_reports():
    # Watch Kyverno PolicyReports
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
                plural="policyreports",  # clusterpolicyreports
                timeout_seconds=TIMEOUT
            ):
                event_type = event["type"]
                if event_type == "MODIFIED":
                    print(f"Received new policy report event: {event}")
                    report = event["object"]
                    name = report.get("metadata", {}).get("name", "Unknown")
                    results = report.get("results", [])
                    message = f"⚠️ *Kyverno Policy Report Alert*\n*Report Name:* {name}\n*Event Type:* {event_type}\n*Violations:* {len(results)}\n"
                    for result in results[:5]:
                        # ({result['status']})\n
                        message += f"- Policy: {result['policy']}  {result['message']}\n"
                    # TODO: CHECK FOR DUPS
                    # send_slack_notification(message)
        except Exception as e:
            print(f"Error watching PolicyReports: {e}")
            # send_slack_notification(
            #     f"⚠️ *Error Watching PolicyReports*\nException: {str(e)}")
        finally:
            watcher.stop()  # Clean up the watcher
        time.sleep(DELAY)  # Back off before retrying


def watch_block_events():
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    script_start_time = datetime.now(timezone.utc)  # Track script start time

    while True:
        try:
            print("Watching Kubernetes events for policy violations...")
            watcher = watch.Watch()
            for event in watcher.stream(v1.list_event_for_all_namespaces, timeout_seconds=TIMEOUT):
                ev = event['object']
                event_time = ev.metadata.creation_timestamp

                # Ignore old events
                if event_time < script_start_time:
                    continue

                reason = ev.reason
                message = ev.message
                involved_object = ev.involved_object
                if reason == "PolicyViolation" or (ev.source.component and "kyverno" in ev.source.component.lower()):
                    if not ev.related:
                        send_slack_notification(f"ev.related = NONE\n{ev}")
                    if not involved_object:
                        send_slack_notification(
                            f"involved_object = NONE\n{ev}")
                    key = f"{ev.related.kind}|{ev.related.name}|{involved_object.namespace}|{involved_object.name}"
                    if is_job_notified(key):
                        print(f"Already notified for key: {key}")
                        send_slack_notification(
                            "Already notified for key: {key}")
                        continue
                    add_to_cache(key)
                    msg = f"🚫 *{ev.related.kind} {ev.related.name} BLOCKED at {event_time}*\n*Namespace:* {involved_object.namespace}\n*Reason:* {reason} -> *{involved_object.kind}:* {involved_object.name}\n*Message:* {message}"
                    send_slack_notification(msg)
        except Exception as e:
            print(f"Error watching events: {e}")
            send_slack_notification(
                f"⚠️ *Error Watching Events*\nException: {str(e)}")
        finally:
            watcher.stop()
            time.sleep(DELAY)


def watch_scan_jobs():
    # Watch kube-bench (BroadcastJob) and kubescape (Job)
    while True:
        config.load_incluster_config()
        batch_api = client.BatchV1Api()
        custom_api = client.CustomObjectsApi()
        try:
            # Watch standard Jobs (e.g., kubescape)
            print(f"Watching standard Jobs in {NAMESPACE}...")
            watcher_jobs = watch.Watch()
            for event in watcher_jobs.stream(
                batch_api.list_namespaced_job,
                namespace=NAMESPACE,
                timeout_seconds=TIMEOUT
            ):
                obj = event["object"]
                name = obj.metadata.name

                if is_job_notified(name):
                    continue  # Skip already notified jobs
                if "kubescape" in name and event["type"] == "MODIFIED":
                    print("Job MODIFIED event!!!")
                    if obj.status.succeeded == 1:
                        send_slack_notification(
                            f"✅ *Scan Completed: {name}*\nCheck the results for details.")
                        add_to_cache(name)
                    elif obj.status.failed is not None and obj.status.failed > 0:
                        send_slack_notification(
                            f"❌ *Scan Failed: {name}*\nCheck the logs for details.")
        except Exception as e:
            print(f"Error watching scan jobs:{e}")
            send_slack_notification(
                f"⚠️ *Error Watching Scan Jobs*\nException: {str(e)}")
            time.sleep(DELAY)

        try:
            # Watch BroadcastJobs (e.g., kube-bench)
            print(f"Watching BroadcastJobs in {NAMESPACE}...")
            watcher_broadcast = watch.Watch()
            for event in watcher_broadcast.stream(
                custom_api.list_namespaced_custom_object,
                group="apps.kruise.io",
                version="v1alpha1",
                namespace=NAMESPACE,
                plural="broadcastjobs",
                timeout_seconds=TIMEOUT
            ):

                obj = event["object"]
                name = obj["metadata"]["name"]
                event_type = event["type"]
                print(f"BroadcastJobs Event!!!! type:", event_type)

                if is_job_notified(name):
                    continue  # Skip already notified jobs
                if "kubebench-scan" in name and event_type == "MODIFIED":
                    obj_status = obj["status"]
                    desired = obj_status.get("desired", 0)
                    completed = obj_status.get("succeeded", 0)
                    failed = obj_status.get("failed", 0)
                    phase = obj_status.get("phase", obj_status)
                    print(
                        f"broadcast job phase: {phase} - desired: {desired} - completed: {completed} - failed: {failed}")

                    if completed == desired and phase == "completed":
                        send_slack_notification(
                            f"✅ *Scan Completed: {name}*\nCompleted on {completed} nodes.")
                        add_to_cache(name)
                    elif failed > 0:
                        send_slack_notification(
                            f"❌ *Scan Failed: {name}*\nFailed on {failed} nodes.")
        except Exception as e:
            print(f"Error watching scan broadcastjobs:{e}")
            send_slack_notification(
                f"⚠️ *Error Watching Scan Broadcastjobs*\nException: {str(e)}")
            time.sleep(DELAY)
        finally:
            # Ensure watchers are stopped if an exception occurs
            if 'watcher_jobs' in locals():
                watcher_jobs.stop()
            if 'watcher_broadcast' in locals():
                watcher_broadcast.stop()
            time.sleep(DELAY)


if __name__ == "__main__":
    print("Preparing Watch...")

    policy_thread = threading.Thread(target=watch_policy_reports, daemon=True)
    job_thread = threading.Thread(target=watch_scan_jobs, daemon=True)

    policy_thread.start()
    job_thread.start()

    event_thread = threading.Thread(target=watch_block_events, daemon=True)
    event_thread.start()

    print("Watching started...")

    while True:
        time.sleep(1)
