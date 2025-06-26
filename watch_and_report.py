from kubernetes import client, config, watch
import os
import requests
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
import json
import yaml
from google.cloud import storage
import tempfile
from generate_report import SecurityReportAnalyzer
import difflib


class SecurityMonitor:
    def __init__(self):
        self.scan_status = {"kubebench": False, "kubescape": False}
        self.report_analyzer = SecurityReportAnalyzer()
        self.lock = threading.Lock()

        # Initialize Kubernetes config
        config.load_incluster_config()
        self.batch_api = client.BatchV1Api()
        self.custom_api = client.CustomObjectsApi()

        # Constants from original watch_and_alert.py
        self.SLACK_TOKEN = os.getenv("SLACK_TOKEN")
        if not self.SLACK_TOKEN:
            raise ValueError("SLACK_TOKEN environment variable is not set")
        self.SLACK_CHANNEL = "C08KHSY23N1"
        self.NAMESPACE = "osc-test"
        self.SLACK_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
        self.RETRIES = 3
        self.DELAY = 5
        self.TIMEOUT = 6

        # Add new instance variables for policy report watching
        self.script_start_time = datetime.now(timezone.utc)
        self.notified_jobs = OrderedDict()
        self.CACHE_MAX_SIZE = 300

    def send_slack_notification(self, message):
        for attempt in range(self.RETRIES):
            response = requests.post(
                self.SLACK_MESSAGE_URL,
                headers={"Authorization": f"Bearer {self.SLACK_TOKEN}"},
                json={"channel": self.SLACK_CHANNEL, "text": message},
            )
            if response.status_code == 200:
                print("Notification sent successfully.")
                return
            print(
                f"Failed to send notification: {response.status_code}, {response.text}"
            )
            time.sleep(self.DELAY)
        print("Failed to send notification after retries.")

    def get_latest_scan_file(self, prefix: str) -> str | None:
        """Get the latest scan file from GCS bucket for a given prefix."""
        try:
            storage_client = storage.Client()
            bucket = storage_client.bucket("kubegrc")
            blobs = bucket.list_blobs(prefix=f"scan-results/{prefix}/")

            latest_blob = None
            latest_time = None

            for blob in blobs:
                if blob.name.endswith(".json"):
                    if latest_time is None or blob.time_created > latest_time:
                        latest_time = blob.time_created
                        latest_blob = blob

            if latest_blob:
                # Create a temporary file
                temp_file = tempfile.NamedTemporaryFile(
                    delete=False, suffix=".json")
                latest_blob.download_to_filename(temp_file.name)
                return temp_file.name
            return None
        except Exception as e:
            print(f"Error fetching latest {prefix} scan file: {e}")
            return None

    def upload_report_to_gcs(self, report_content: str, timestamp: str):
        """Upload the generated report to GCS bucket."""
        try:
            storage_client = storage.Client()
            bucket = storage_client.bucket("kubegrc")
            blob = bucket.blob(
                f"scan-results/security-report/security-report-{timestamp}.md"
            )
            blob.upload_from_string(
                report_content.encode("utf-8"), content_type="text/markdown"
            )
            return f"gs://kubegrc/scan-results/security-report/security-report-{timestamp}.md"
        except Exception as e:
            print(f"Error uploading report to GCS: {e}")
            return None

    def get_last_report(self) -> str | None:
        """Downloads the previous report from GCS and returns local file path."""
        try:
            storage_client = storage.Client()
            bucket = storage_client.bucket("kubegrc")
            blobs = list(bucket.list_blobs(
                prefix="scan-results/security-report/"))

            reports = [blob for blob in blobs if blob.name.endswith(".md")]
            reports.sort(key=lambda b: b.time_created, reverse=True)

            if reports:
                last_report = reports[0]  # Most recent
                report_content = last_report.download_as_text(encoding="utf-8")
                return report_content
            else:
                return None
        except Exception as e:
            print(f"Error fetching previous report: {e}")
            return None

    def compute_markdown_diff(self, old_content: str, new_content: str) -> str:
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="Previous Report",
            tofile="Current Report",
            lineterm="",
        )
        diff_output = "\n".join(list(diff))

        # Optional: reduce verbosity or highlight only significant changes
        return diff_output  # if diff_output.strip() else None

    def check_and_generate_report(self):
        with self.lock:
            if all(self.scan_status.values()):
                print("Both scans completed, generating report...")
                try:
                    # Get latest scan files
                    kubebench_file = self.get_latest_scan_file("kubebench")
                    kubescape_file = self.get_latest_scan_file("kubescape")

                    if not kubebench_file or not kubescape_file:
                        raise Exception(
                            "Could not fetch latest scan files from GCS")

                    last_report = self.get_last_report()

                    # Generate report
                    local_new_report, diff_summary = (
                        self.report_analyzer.generate_report(
                            kubebench_file, kubescape_file, last_report
                        )
                    )

                    # Generate timestamp for the report
                    timestamp = datetime.now(
                        timezone.utc).strftime("%Y%m%d-%H%M%S")

                    # Upload report to GCS
                    report_path = self.upload_report_to_gcs(
                        local_new_report, timestamp)

                    if report_path:
                        msg = f"✅ *Security Report Generated*\nReport available at: {report_path}\n*New changes*:\n{diff_summary}"
                        self.send_slack_notification(msg)
                    else:
                        raise Exception("Failed to upload report to GCS")

                    # Clean up temporary files
                    os.unlink(kubebench_file)
                    os.unlink(kubescape_file)

                    # Reset scan status
                    self.scan_status = {"kubebench": False, "kubescape": False}

                except Exception as e:
                    self.send_slack_notification(
                        f"❌ *Error Generating Report*\nException: {str(e)}"
                    )

    def watch_scan_jobs(self):
        while True:
            print("Watching scan results...")
            try:
                # Watch standard Jobs (kubescape)
                watcher_jobs = watch.Watch()
                for event in watcher_jobs.stream(
                    self.batch_api.list_namespaced_job,
                    namespace=self.NAMESPACE,
                    timeout_seconds=self.TIMEOUT,
                ):
                    obj = event["object"]
                    name = obj.metadata.name

                    if self.is_job_notified(name):
                        continue
                    if "kubescape" in name and event["type"] == "MODIFIED":
                        if obj.status.succeeded == 1:
                            with self.lock:
                                self.scan_status["kubescape"] = True
                            self.send_slack_notification(
                                f"✅ *Kubescape Scan ({name}) Completed*"
                            )
                            self.add_to_cache(name)
                            # self.check_and_generate_report()
                            threading.Thread(
                                target=self.check_and_generate_report, daemon=True
                            ).start()
                        elif obj.status.failed is not None and obj.status.failed > 0:
                            self.send_slack_notification(
                                f"❌ *Kubescape Scan Failed*")

                # Watch BroadcastJobs (kube-bench)
                watcher_broadcast = watch.Watch()
                for event in watcher_broadcast.stream(
                    self.custom_api.list_namespaced_custom_object,
                    group="apps.kruise.io",
                    version="v1alpha1",
                    namespace=self.NAMESPACE,
                    plural="broadcastjobs",
                    timeout_seconds=self.TIMEOUT,
                ):
                    obj = event["object"]
                    name = obj["metadata"]["name"]

                    if self.is_job_notified(name):
                        continue
                    if "kubebench-scan" in name and event["type"] == "MODIFIED":
                        obj_status = obj["status"]
                        desired = obj_status.get("desired", 0)
                        completed = obj_status.get("succeeded", 0)
                        failed = obj_status.get("failed", 0)
                        phase = obj_status.get("phase", obj_status)

                        if completed == desired and phase == "completed":
                            with self.lock:
                                self.scan_status["kubebench"] = True
                            self.send_slack_notification(
                                f"✅ *Kube-bench Scan ({name}) Completed on {completed} Nodes*"
                            )
                            self.add_to_cache(name)
                            # self.check_and_generate_report()
                            threading.Thread(
                                target=self.check_and_generate_report, daemon=True
                            ).start()
                        elif failed > 0:
                            self.send_slack_notification(
                                f"❌ *Kube-bench Scan Failed*\nCheck the logs for details."
                            )

            except Exception as e:
                print(f"Error watching scan jobs: {e}")
                self.send_slack_notification(
                    f"⚠️ *Error Watching Scan Jobs*\nException: {str(e)}"
                )
                time.sleep(self.DELAY)
            finally:
                if "watcher_jobs" in locals():
                    watcher_jobs.stop()
                if "watcher_broadcast" in locals():
                    watcher_broadcast.stop()
                time.sleep(self.DELAY)

    def add_to_cache(self, job_name):
        """Add job to notification cache with timestamp."""
        self.notified_jobs[job_name] = time.time()
        if len(self.notified_jobs) > self.CACHE_MAX_SIZE:
            self.notified_jobs.popitem(last=False)

    def is_job_notified(self, job_name):
        """Check if job has already been notified."""
        return job_name in self.notified_jobs

    def watch_block_events(self):
        """Watch Kubernetes events for policy violations."""
        v1 = client.CoreV1Api()

        while True:
            try:
                print("Watching Kubernetes events for policy violations...")
                watcher = watch.Watch()
                for event in watcher.stream(
                    v1.list_event_for_all_namespaces, timeout_seconds=self.TIMEOUT
                ):
                    ev = event["object"]
                    event_time = ev.metadata.creation_timestamp

                    # Ignore old events
                    if event_time < self.script_start_time:
                        continue

                    reason = ev.reason
                    message = ev.message
                    involved_object = ev.involved_object

                    if reason == "PolicyViolation" or (
                        ev.source.component and "kyverno" in ev.source.component.lower()
                    ):
                        if not ev.related or not involved_object:
                            continue

                        key = f"{ev.related.kind}|{ev.related.name}|{involved_object.namespace}|{involved_object.name}"
                        if self.is_job_notified(key):
                            print(f"Already notified for key: {key}")
                            continue

                        self.add_to_cache(key)
                        msg = f"🚫 *{ev.related.kind} {ev.related.name} BLOCKED at {event_time}*\n*Namespace:* {involved_object.namespace}\n*Reason:* {reason} -> *{involved_object.kind}:* {involved_object.name}\n*Message:* {message}"
                        self.send_slack_notification(msg)
            except Exception as e:
                print(f"Error watching events: {e}")
                self.send_slack_notification(
                    f"⚠️ *Error Watching Events*\nException: {str(e)}"
                )
            finally:
                if "watcher" in locals():
                    watcher.stop()
                time.sleep(self.DELAY)

    def get_latest_policy_report(self):
        """Get the latest policy report from GCS bucket."""
        try:
            storage_client = storage.Client()
            bucket = storage_client.bucket("kubegrc")
            blobs = bucket.list_blobs(
                prefix="scan-results/kyverno/kyverno_policy_report_"
            )

            latest_blob = None
            latest_time = None

            for blob in blobs:
                if blob.name.endswith(".yaml"):
                    if latest_time is None or blob.time_created > latest_time:
                        latest_time = blob.time_created
                        latest_blob = blob

            if latest_blob:
                full_path = latest_blob.name
                # Create directories if they don't exist
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                latest_blob.download_to_filename(full_path)
                return full_path
            return None
        except Exception as e:
            print(f"Error fetching latest policy report: {e}")
            return None

    def send_policy_report_notification(self, report_file):
        """Process and send notification for a policy report."""
        try:
            with open(report_file, "r") as f:
                report = yaml.safe_load(f)

            results = report.get("results", [])
            violations = sum(1 for r in results if r.get("result") == "fail")
            passes = sum(1 for r in results if r.get("result") == "pass")

            message = f"📊 *New Kyverno Policy Report*\n"
            message += f"*Total Checks:* {len(results)}\n"
            message += f"*Passed:* {passes} ✅\n"
            message += f"*Failed:* {violations} ❌\n"
            message += (
                f"*For more details check the bucket:* gs://kubegrc/{report_file}\n"
            )

            self.send_slack_notification(message)
        except Exception as e:
            print(f"Error processing policy report notification: {e}")

    def process_latest_policy_report(self):
        """Process the latest policy report and send notification."""
        report_file = self.get_latest_policy_report()
        if report_file:
            try:
                self.send_policy_report_notification(report_file)
            finally:
                os.unlink(report_file)
        else:
            print("No policy reports found in the bucket")


def main():
    print("[+] Preparing Watch...")

    monitor = SecurityMonitor()

    # Process the latest policy report
    monitor.process_latest_policy_report()

    # Start the block events watcher in a separate thread
    block_events_thread = threading.Thread(
        target=monitor.watch_block_events, daemon=True
    )
    block_events_thread.start()

    # Start the scan jobs watcher
    scan_jobs_thread = threading.Thread(
        target=monitor.watch_scan_jobs, daemon=True)
    scan_jobs_thread.start()

    print("[+] Watching started correctly...")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
