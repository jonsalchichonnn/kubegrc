import json
from collections import defaultdict
from typing import Dict, Any
import re
import difflib

class SecurityReportAnalyzer:
    def __init__(self):
        self.risk_levels = {
            'High': {'threshold': 10, 'color': '\033[91m'},  # Red
            'Medium': {'threshold': 5, 'color': '\033[93m'},  # Yellow
            'Low': {'threshold': 0, 'color': '\033[92m'}     # Green
        }
        self.reset_color = '\033[0m'

    def load_json_file(self, file_path: str) -> dict:
        """Load and parse a JSON file, handling potential formatting issues."""
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                node_info = None
                
                # Extract node information if present
                if content.startswith('Running kube-bench on node:'):
                    node_line = content.split('\n')[0]
                    node_info = node_line.replace('Running kube-bench on node:', '').strip()
                    # Find the first occurrence of '{' for JSON content
                    start_idx = content.find('{')
                    if start_idx != -1:
                        content = content[start_idx:]
                    else:
                        return {'node': node_info}
                
                try:
                    data = json.loads(content)
                    # Add node information to the data if it was found
                    if node_info:
                        data['node'] = node_info
                    return data
                except json.JSONDecodeError:
                    # If that fails, try to parse line by line
                    data = []
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and line.startswith('{'):
                            try:
                                data.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    result = data[0] if data else {}
                    if node_info:
                        result['node'] = node_info
                    return result
        except Exception as e:
            print(f"Error loading {file_path}: {str(e)}")
            return {}

    def calculate_risk_level(self, fails: int, warnings: int) -> str:
        """Calculate risk level based on number of fails and warnings."""
        # Normalize kubescape results (assuming average of 100 resources per cluster)
        # and kube-bench results (typically 50-100 tests)
        normalized_fails = fails / 100  # Normalize to a 0-1 scale
        
        # Warnings count as half of fails
        total_issues = normalized_fails + (warnings * 0.5)
        
        for level, criteria in self.risk_levels.items():
            if total_issues >= criteria['threshold']:
                return level
        return 'low'

    def analyze_kubebench(self, kubebench_data: dict) -> Dict[str, Any]:
        """Analyze kubebench data and return structured findings."""
        processed_controls = defaultdict(lambda: defaultdict(list))
        controls = kubebench_data.get('Controls', [])

        for control in controls:
            control_title = f"{control.get('id')} - {control.get('text')}"
            for test in control.get('tests', []):
                for result in test.get('results', []):
                    if result.get('status') in ['FAIL', 'WARN']:
                        finding = {
                            'test_number': result.get('test_number', ''),
                            'description': result.get('test_desc', ''),
                            'status': result.get('status', ''),
                            'remediation': result.get('remediation', '')
                        }
                        
                        # Group by node and namespace
                        node = kubebench_data.get('node', 'unknown')
                        namespace = 'kube-system'  # Default namespace for kubebench
                        resource_id = f"node/{node}"
                        processed_controls[node][control_title].append(finding)
        findings = {
            'controls': processed_controls,
            'totals': kubebench_data.get('Totals', {})
        }
        return findings

    def analyze_kubescape(self, kubescape_data: dict) -> Dict[str, Any]:
        """Analyze kubescape data and return structured findings."""

        resource_counters = kubescape_data.get('summaryDetails').get('ResourceCounters')
        findings = {
            'total_resources': len(kubescape_data.get('results', [])),
            'skipped_resources': resource_counters.get('skippedResources') + resource_counters.get('excludedResources'),
            'controls': [],
            'failed_resources': [],
            'controls_stats': {}
        }

        controls_summary = kubescape_data.get('summaryDetails', {}).get('controls', {})
        controls_stats = {
            'Critical':[],
            'High':[],
            'Medium':[],
            'Low':[]
        }
        controls_severity = {}
        for control_key in controls_summary:
            control = controls_summary[control_key]
            if control['status'] == 'failed':    
                score = control['scoreFactor']
                severity = ''
                if score <= 3 :
                    severity = 'Low'
                elif score <= 6 :
                    severity = 'Medium'
                elif score <= 8 :
                    severity = 'High'
                else:
                    severity = 'Critical'
                controls_severity[control_key] = severity
                controls_stats[severity].append({
                    'control_id': control.get('controlID'),
                    'name': control.get('name'),
                    'risk_score': round(control.get('score')),
                    'compliance_score': round(control.get('complianceScore')),
                    'failed_resources': control.get('ResourceCounters').get('failedResources'),
                    'all_resources': control.get('ResourceCounters').get('failedResources') + control.get('ResourceCounters').get('passedResources'),
                })
        findings['controls_stats'] = controls_stats

        
        # Process failed resources
        resource_map = {r['resourceID']: r for r in kubescape_data.get('resources', [])}
        
        for result in kubescape_data.get('results', []):                    
            failed_controls = []

            for control in result.get('controls', []):
                if control.get('status').get('status') == 'failed':
                    control_id = control['controlID']
                    control_rules = control.get('rules', [])
                    remediations = []
                    for rule in control_rules:
                        if rule.get('status') == 'failed':
                            for path in rule.get('paths', []):
                                remediation = path.get('failedPath', path.get('deletePath', path.get('reviewPath')))
                                if not remediation:
                                    remediation = f"{path.get('fixPath').get('path')}={path.get('fixPath').get('value')}"
                                remediations.append(remediation)

                    failed_controls.append({
                        'severity': controls_severity[control_id],
                        'name': control.get('name'),
                        'control_id': control_id,
                        'remediation': remediations
                    })

            if failed_controls:
                resource = resource_map.get(result.get('resourceID'))
                obj = resource.get('object', {})
                metadata = obj.get('metadata', {})
                failed_resource = {
                        'apiVersion': obj.get('apiVersion', 'N/A'),
                        'kind': obj.get('kind', ''),
                        'name': metadata.get('name', obj.get('name')),
                        'namespace': metadata.get('namespace', 'N/A'),
                        'controls': failed_controls
                    }
                findings['failed_resources'].append(failed_resource)
            
        return findings

    
    def extract_metrics_from_report(self, md_content: str) -> dict:
        patterns = {
            'total_failures': r'\*\*Total Failures\*\*:\s*(\d+)',
            'total_warnings': r'\*\*Total Warnings\*\*:\s*(\d+)',
            'failed_resources': r'Failed Resources:\s*(\d+)',
            'total_resources': r'Total Resources:\s*(\d+)',
            'passed_resources': r'Passed Resources:\s*(\d+)',
        }
        metrics = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, md_content)
            if match:
                metrics[key] = int(match.group(1))
        return metrics

    def format_structured_diff(self, old_metrics: dict, new_metrics: dict) -> str:
        lines = ["## Changes Compared to Previous Report\n"]
        for key in new_metrics:
            old = old_metrics.get(key)
            new = new_metrics[key]
            if old is not None and old != new:
                improved = new < old
                diff = abs(new - old)
                lines.append(
                    f"- **{key.replace('_', ' ').title()}**: ~~{old}~~  **{new}** ({'-' if improved else '+'} {diff})"
                )
        return '\n'.join(lines) if len(lines) > 1 else ""

    def compute_markdown_diff_from_strings(self, old_content: str, new_content: str) -> str:
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        diff = difflib.unified_diff(
            old_lines, new_lines,
            fromfile='Previous Report',
            tofile='Current Report',
            lineterm=''
        )
        return '\n'.join(diff)


    def generate_report(self, kubebench_path: str, kubescape_path: str, previous_report_content=None) -> str:
        # Load both reports
        kubebench_data = self.load_json_file(kubebench_path)
        kubescape_data = self.load_json_file(kubescape_path)
        
        # Analyze both reports
        kubebench_analysis = self.analyze_kubebench(kubebench_data)
        kubescape_analysis = self.analyze_kubescape(kubescape_data)
        
        # Calculate overall risk level
        kubebench_totals = kubebench_data.get('Totals', {})
        kubebench_total_checks = kubebench_totals['total_pass'] + kubebench_totals['total_fail'] + kubebench_totals['total_warn'] + kubebench_totals['total_info']
        kubebench_fail_percentage = round(kubebench_totals['total_fail'] / kubebench_total_checks * 100, 2)

        kubescape_totals = kubescape_analysis['total_resources']
        kubescape_failed_resources = kubescape_analysis['failed_resources']
        kubescape_fails = len(kubescape_failed_resources)
        kubescape_fail_percentage = round(kubescape_fails / kubescape_totals * 100, 2)
        kubescape_pass = kubescape_totals - kubescape_fails

        total_fails = kubebench_totals.get('total_fail') + kubescape_fails
        risk_level = self.calculate_risk_level(total_fails, kubebench_totals.get('total_warn'))
        
        # Generate report sections
        report_sections = []
        
        # 1. Executive Summary
        report_sections.append(f"""
# Kubernetes Security Assessment Report

## Executive Summary
- **Overall Risk Level**: {risk_level}
- **Total Failures**: {total_fails}
- **Total Warnings**: {kubebench_totals.get('total_warn')}
- **Kube-bench Scan Results**:
  - Total Checks: {kubebench_total_checks}
  - Failures: {kubebench_totals['total_fail']} ({kubebench_fail_percentage}%)
  - Warnings: {kubebench_totals['total_warn']}
  - Informational: {kubebench_totals['total_info']}
- **Kubescape Scan Results**:
  - Total Resources: {kubescape_totals}
  - Failed Resources: {kubescape_fails} ({kubescape_fail_percentage}%)
  - Passed Resources: {kubescape_pass}
  - Skipped Resources: {kubescape_analysis['skipped_resources']}
""")

        # 2. Kube-Bench Detailed Findings
        report_sections.append("## Kube-bench Findings")
        
        for control in kubebench_data.get('Controls'):     
            if control['total_fail'] > 0 or control['total_warn'] > 0:
                report_sections.append(f"""
### Control {control['id']}: {control['text']}
""")
                for test in control['tests']:
                    if test['fail'] > 0 or test['warn'] > 0:
                        report_sections.append(f"""
#### **{test['desc']}**
- **Section**: {test['section']}
- **Failures**: {test['fail']}
- **Warnings**: {test['warn']}

**Findings:**
""")
                        for result in test['results']:
                            if result['status'] in ['FAIL', 'WARN']:
                                remediation_text = self.format_remediation(result['remediation'])
                                if isinstance(remediation_text, str):
                                    remediation_lines = remediation_text.splitlines()
                                    if remediation_lines:
                                        remediation_md = remediation_lines[0]
                                        if len(remediation_lines) > 1:
                                            remediation_md += '\n' + '\n'.join([f"    {line}" if line.strip() else '' for line in remediation_lines[1:]])
                                    else:
                                        remediation_md = ''
                                else:
                                    remediation_md = remediation_text
                                report_sections.append(f"""
- **Test {result['test_number']}**: {result['test_desc']}
  - **Status**: {result['status']}
  - **Reason**: <br>{result['reason']}
  - **Remediation**:<br>{remediation_md}
""")

        # 3. Kubescape Controls
        report_sections.append("""
## Kubescape Findings
## Details
| Severity | Control ID | Control Name | Failed Resources | All Resources | Risk Score (%) | Compliance Score (%) |
|----------|------------|--------------|------------------|---------------|-----------------|---------------------|""")
        
        for control_severity in kubescape_analysis['controls_stats']:
            for control in kubescape_analysis['controls_stats'][control_severity]:
                docs_link = f"[C-{control['control_id'].split('-')[-1]}](https://hub.armosec.io/docs/{control['control_id']})"
                report_sections.append(
                    f"| {control_severity} | {control['control_id']} | {control['name']} | {control['failed_resources']} | {control['all_resources']} | {control['risk_score']} | {control['compliance_score']} |"
                )

        # 4. Failed Resources
        report_sections.append("""
## Failed Resources
""")
        
        for resource in kubescape_analysis['failed_resources']:
            if not resource['controls']:
                continue
            report_sections.append(f"""
### Name: **{resource['name']}**
- **ApiVersion**: {resource['apiVersion']}
- **Kind**: {resource['kind']}
- **Namespace**: {resource['namespace']}
""")
            report_sections.append("| **Severity** | **Name** | **Docs** | **Assisted Remediation** |\n|--------------|----------|----------|-------------------------|")
            
            for control in resource['controls']:
                docs_link = f"[C-{control['control_id'].split('-')[-1]}](https://hub.armosec.io/docs/{control['control_id']})" if control['control_id'] else ""
                # Assisted Remediation: join all failed paths, or show as list
                assisted_remediation = "<br>".join(control['remediation'])
                report_sections.append(
                    f"| {control['severity']} | {control['name']} | {docs_link} | {assisted_remediation} |"
                )

        # 5. Recommendations
        report_sections.append("""
## Recommendations
1. Address all FAIL findings from Kube-Bench as they represent critical security issues
2. Review and remediate WARN findings based on your security requirements
3. Implement the suggested remediations for Kubescape findings
4. Regularly run security scans to maintain compliance
""")

        report_body = "\n".join(report_sections)
        possible_summary = 'None'
        # Compare with previous report if available
        if previous_report_content:
            old_metrics = self.extract_metrics_from_report(previous_report_content)
            new_metrics = self.extract_metrics_from_report(report_body)
            structured_summary = self.format_structured_diff(old_metrics, new_metrics)
            if structured_summary:
                report_body += "\n\n" + structured_summary
                possible_summary = structured_summary

            raw_diff = self.compute_markdown_diff_from_strings(previous_report_content, report_body)
            if raw_diff:
                report_body += "\n\n**<details><summary>Show Full Markdown Diff</summary>**\n\n"
                report_body += "```diff\n" + raw_diff + "\n```\n</details>"

        return report_body, possible_summary

    def escape_template_strings(self, text):
        """Escape template strings in the text by replacing ${var} with \\${var} and wrap URLs in backticks"""
        # First escape the template variables
        text = re.sub(r'\${([^}]+)}', r'\\${\1}', text)
        # Then wrap URLs in backticks to prevent markdown link conversion
        # Look for URLs that might be in parentheses or quotes
        text = re.sub(r'([("])(https?://[^\s"\)]+)([")])', r'\1`\2`\3', text)
        # Handle standalone URLs
        text = re.sub(r'(?<![("])(https?://[^\s]+)(?![")])', r'`\1`', text)
        return text

    def format_remediation(self, remediation):
        """Format remediation text with proper escaping of template strings"""
        if isinstance(remediation, str):
            return self.escape_template_strings(remediation)
        return remediation

def main():
    analyzer = SecurityReportAnalyzer()
    report = analyzer.generate_report('kubebench.json', 'kubescape.json')
    
    # Save to file with .md extension
    with open('security_report.md', 'w') as f:
        f.write(report)

if __name__ == "__main__":
    main()