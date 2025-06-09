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
        self.scan_status = {
            'kubebench': False,
            'kubescape': False
        }
        self.report_analyzer = SecurityReportAnalyzer()
        self.lock = threading.Lock()
        
        # Initialize Kubernetes config
        config.load_incluster_config()
        self.batch_api = client.BatchV1Api()
        self.custom_api = client.CustomObjectsApi()
        
        # Constants from original watch_and_alert.py
        self.SLACK_TOKEN = os.getenv('SLACK_TOKEN')
        if not self.SLACK_TOKEN:
            raise ValueError("SLACK_TOKEN environment variable is not set")
        self.SLACK_CHANNEL = "C08KHSY23N1"
        self.NAMESPACE = "osc-test"
        self.SLACK_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
        self.RETRIES = 3
        self.DELAY = 5
        self.TIMEOUT = 6

    def send_slack_notification(self, message):
        for attempt in range(self.RETRIES):
            response = requests.post(
                self.SLACK_MESSAGE_URL,
                headers={"Authorization": f"Bearer {self.SLACK_TOKEN}"},
                json={"channel": self.SLACK_CHANNEL, "text": message}
            )
            if response.status_code == 200:
                print("Notification sent successfully.")
                return
            print(f"Failed to send notification: {response.status_code}, {response.text}")
            time.sleep(self.DELAY)
        print("Failed to send notification after retries.")

    def get_latest_scan_file(self, prefix: str) -> str:
        """Get the latest scan file from GCS bucket for a given prefix."""
        try:
            storage_client = storage.Client()
            bucket = storage_client.bucket('kubegrc')
            blobs = bucket.list_blobs(prefix=f'scan-results/{prefix}/')
            
            latest_blob = None
            latest_time = None
            
            for blob in blobs:
                if blob.name.endswith('.json'):
                    if latest_time is None or blob.time_created > latest_time:
                        latest_time = blob.time_created
                        latest_blob = blob
            
            if latest_blob:
                # Create a temporary file
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
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
            bucket = storage_client.bucket('kubegrc')
            blob = bucket.blob(f'scan-results/security-report/security-report-{timestamp}.md')
            blob.upload_from_string(report_content.encode('utf-8'), content_type="text/markdown")
            return f"gs://kubegrc/scan-results/security-report/security-report-{timestamp}.md"
        except Exception as e:
            print(f"Error uploading report to GCS: {e}")
            return None

    def get_last_report(self) -> str:
        """Downloads the previous report from GCS and returns local file path."""
        try:
            storage_client = storage.Client()
            bucket = storage_client.bucket('kubegrc')
            blobs = list(bucket.list_blobs(prefix='scan-results/security-report/'))
            
            reports = [blob for blob in blobs if blob.name.endswith('.md')]
            reports.sort(key=lambda b: b.time_created, reverse=True)

            if reports:
                last_report = reports[0]  # Most recent
                report_content = last_report.download_as_text(encoding='utf-8')
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
            old_lines, new_lines,
            fromfile='Previous Report',
            tofile='Current Report',
            lineterm=''
        )
        diff_output = '\n'.join(list(diff))
        
        # Optional: reduce verbosity or highlight only significant changes
        return diff_output #if diff_output.strip() else None


    def check_and_generate_report(self):
        with self.lock:
            if all(self.scan_status.values()):
                print("Both scans completed, generating report...")
                try:
                    # Get latest scan files
                    kubebench_file = self.get_latest_scan_file('kubebench')
                    kubescape_file = self.get_latest_scan_file('kubescape')
                    
                    if not kubebench_file or not kubescape_file:
                        raise Exception("Could not fetch latest scan files from GCS")
                    
                    last_report = self.get_last_report()
                    # Generate report
                    local_new_report, diff_summary = self.report_analyzer.generate_report(kubebench_file, kubescape_file, last_report)
                    
                    # diff_summary = None
                    # if last_report:
                    #     diff_summary = self.compute_markdown_diff(last_report, local_new_report)

                    # short_diff = ''
                    # if diff_summary:
                    #     short_diff = 'New changes:\n' + '\n'.join(diff_summary.splitlines()[:20])
                    #     local_new_report = 'New changes:\n```diff\n' + diff_summary + "\n```" + local_new_report


                    # Generate timestamp for the report
                    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
                    
                    # Upload report to GCS
                    report_path = self.upload_report_to_gcs(local_new_report, timestamp)
                    
                    if report_path:
                        msg = f"✅ *Security Report Generated*\nReport available at: {report_path}\n*New changes*:\n{diff_summary}"
                        self.send_slack_notification(msg)
                        # self.send_slack_notification(msg + short_diff)
                    else:
                        raise Exception("Failed to upload report to GCS")
                    
                    # Clean up temporary files
                    os.unlink(kubebench_file)
                    os.unlink(kubescape_file)
                    
                    # Reset scan status
                    self.scan_status = {'kubebench': False, 'kubescape': False}
                    
                except Exception as e:
                    self.send_slack_notification(f"❌ *Error Generating Report*\nException: {str(e)}")

    def watch_scan_jobs(self):
        while True:
            try:
                # Watch standard Jobs (kubescape)
                watcher_jobs = watch.Watch()
                for event in watcher_jobs.stream(
                    self.batch_api.list_namespaced_job,
                    namespace=self.NAMESPACE,
                    timeout_seconds=self.TIMEOUT
                ):
                    obj = event["object"]
                    name = obj.metadata.name

                    if "kubescape" in name and event["type"] == "MODIFIED":
                        if obj.status.succeeded == 1:
                            with self.lock:
                                self.scan_status['kubescape'] = True
                            self.send_slack_notification(f"✅ *Kubescape Scan Completed*")
                            self.check_and_generate_report()
                        elif obj.status.failed is not None and obj.status.failed > 0:
                            self.send_slack_notification(f"❌ *Kubescape Scan Failed*")

                # Watch BroadcastJobs (kube-bench)
                watcher_broadcast = watch.Watch()
                for event in watcher_broadcast.stream(
                    self.custom_api.list_namespaced_custom_object,
                    group="apps.kruise.io",
                    version="v1alpha1",
                    namespace=self.NAMESPACE,
                    plural="broadcastjobs",
                    timeout_seconds=self.TIMEOUT
                ):
                    obj = event["object"]
                    name = obj["metadata"]["name"]
                    
                    if "kubebench-scan" in name and event["type"] == "MODIFIED":
                        obj_status = obj["status"]
                        desired = obj_status.get("desired", 0)
                        completed = obj_status.get("succeeded", 0)
                        failed = obj_status.get("failed", 0)
                        phase = obj_status.get("phase", obj_status)

                        if completed == desired and phase == "completed":
                            with self.lock:
                                self.scan_status['kubebench'] = True
                            self.send_slack_notification(f"✅ *Kube-bench Scan Completed*")
                            self.check_and_generate_report()
                        elif failed > 0:
                            self.send_slack_notification(f"❌ *Kube-bench Scan Failed*")

            except Exception as e:
                print(f"Error watching scan jobs: {e}")
                self.send_slack_notification(f"⚠️ *Error Watching Scan Jobs*\nException: {str(e)}")
                time.sleep(self.DELAY)
            finally:
                if 'watcher_jobs' in locals():
                    watcher_jobs.stop()
                if 'watcher_broadcast' in locals():
                    watcher_broadcast.stop()
                time.sleep(self.DELAY)

def main():
    monitor = SecurityMonitor()
    # monitor.watch_scan_jobs()
    monitor.scan_status['kubebench'] = True
    monitor.scan_status['kubescape'] = True
    monitor.check_and_generate_report()

if __name__ == "__main__":
    main() 