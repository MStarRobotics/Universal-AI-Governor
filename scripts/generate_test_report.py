#!/usr/bin/env python3
"""
Comprehensive Test Report Generator
Analyzes test results from hardware integration CI and generates detailed reports
"""

import json
import os
import sys
import glob
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse

class TestReportGenerator:
    def __init__(self, artifacts_dir: str = "."):
        self.artifacts_dir = Path(artifacts_dir)
        self.report_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "hardware_tests": {},
            "security_analysis": {},
            "performance_metrics": {},
            "documentation_status": {},
            "recommendations": []
        }

    def analyze_hardware_tests(self) -> None:
        """Analyze hardware integration test results"""
        print("📊 Analyzing hardware integration test results...")
        
        test_files = list(self.artifacts_dir.glob("**/hardware-tests-*.json"))
        
        hardware_configs = {
            "all-hardware": {"passed": 0, "failed": 0, "total": 0},
            "tmp-only": {"passed": 0, "failed": 0, "total": 0},
            "enclave-only": {"passed": 0, "failed": 0, "total": 0},
            "software-fallback": {"passed": 0, "failed": 0, "total": 0},
            "tamper-simulation": {"passed": 0, "failed": 0, "total": 0}
        }
        
        platform_results = {
            "ubuntu-latest": {"passed": 0, "failed": 0},
            "windows-latest": {"passed": 0, "failed": 0},
            "macos-latest": {"passed": 0, "failed": 0}
        }
        
        for test_file in test_files:
            try:
                with open(test_file, 'r') as f:
                    test_data = json.load(f)
                
                # Extract platform and config from filename
                filename = test_file.name
                parts = filename.replace("hardware-tests-", "").replace(".json", "").split("-")
                platform = parts[0] if parts else "unknown"
                config = "-".join(parts[1:]) if len(parts) > 1 else "unknown"
                
                # Analyze test results
                if isinstance(test_data, dict) and "tests" in test_data:
                    for test in test_data["tests"]:
                        if config in hardware_configs:
                            hardware_configs[config]["total"] += 1
                            if test.get("result") == "ok":
                                hardware_configs[config]["passed"] += 1
                                if platform in platform_results:
                                    platform_results[platform]["passed"] += 1
                            else:
                                hardware_configs[config]["failed"] += 1
                                if platform in platform_results:
                                    platform_results[platform]["failed"] += 1
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"⚠️ Error reading test file {test_file}: {e}")
        
        self.report_data["hardware_tests"] = {
            "configurations": hardware_configs,
            "platforms": platform_results,
            "total_test_files": len(test_files)
        }
        
        # Generate recommendations based on results
        for config, results in hardware_configs.items():
            if results["total"] > 0:
                success_rate = results["passed"] / results["total"]
                if success_rate < 0.9:
                    self.report_data["recommendations"].append(
                        f"⚠️ {config} configuration has {success_rate:.1%} success rate - investigate failures"
                    )

    def analyze_security_results(self) -> None:
        """Analyze security audit and compliance results"""
        print("🔒 Analyzing security audit results...")
        
        security_files = {
            "audit": self.artifacts_dir / "security-audit.json",
            "dependencies": self.artifacts_dir / "dependency-analysis.json",
            "unsafe_code": self.artifacts_dir / "unsafe-analysis.json"
        }
        
        security_summary = {
            "vulnerabilities": {"high": 0, "medium": 0, "low": 0},
            "dependency_issues": 0,
            "unsafe_code_blocks": 0,
            "compliance_status": "unknown"
        }
        
        # Analyze security audit
        if security_files["audit"].exists():
            try:
                with open(security_files["audit"], 'r') as f:
                    audit_data = json.load(f)
                
                if "vulnerabilities" in audit_data:
                    for vuln in audit_data["vulnerabilities"]:
                        severity = vuln.get("advisory", {}).get("severity", "low").lower()
                        if severity in security_summary["vulnerabilities"]:
                            security_summary["vulnerabilities"][severity] += 1
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"⚠️ Error reading security audit: {e}")
        
        # Analyze dependency issues
        if security_files["dependencies"].exists():
            try:
                with open(security_files["dependencies"], 'r') as f:
                    dep_data = json.load(f)
                
                if "bans" in dep_data:
                    security_summary["dependency_issues"] = len(dep_data["bans"])
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"⚠️ Error reading dependency analysis: {e}")
        
        # Analyze unsafe code
        if security_files["unsafe_code"].exists():
            try:
                with open(security_files["unsafe_code"], 'r') as f:
                    unsafe_data = json.load(f)
                
                if "used" in unsafe_data:
                    security_summary["unsafe_code_blocks"] = unsafe_data["used"]
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"⚠️ Error reading unsafe code analysis: {e}")
        
        self.report_data["security_analysis"] = security_summary
        
        # Security recommendations
        total_vulns = sum(security_summary["vulnerabilities"].values())
        if total_vulns > 0:
            self.report_data["recommendations"].append(
                f"🚨 {total_vulns} security vulnerabilities found - review and patch immediately"
            )
        
        if security_summary["dependency_issues"] > 0:
            self.report_data["recommendations"].append(
                f"⚠️ {security_summary['dependency_issues']} dependency issues found"
            )

    def analyze_performance_metrics(self) -> None:
        """Analyze performance benchmark results"""
        print("⚡ Analyzing performance metrics...")
        
        perf_files = list(self.artifacts_dir.glob("**/performance-results.json"))
        
        performance_summary = {
            "benchmarks": {},
            "regressions": [],
            "improvements": [],
            "memory_leaks": False
        }
        
        for perf_file in perf_files:
            try:
                with open(perf_file, 'r') as f:
                    perf_data = json.load(f)
                
                # Extract benchmark results
                if "benchmarks" in perf_data:
                    for benchmark in perf_data["benchmarks"]:
                        name = benchmark.get("name", "unknown")
                        mean_time = benchmark.get("mean", {}).get("estimate", 0)
                        performance_summary["benchmarks"][name] = {
                            "mean_time_ns": mean_time,
                            "throughput": benchmark.get("throughput", {})
                        }
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"⚠️ Error reading performance file {perf_file}: {e}")
        
        # Check for memory leaks
        valgrind_files = list(self.artifacts_dir.glob("**/valgrind-results.txt"))
        for valgrind_file in valgrind_files:
            try:
                with open(valgrind_file, 'r') as f:
                    valgrind_output = f.read()
                
                if "definitely lost" in valgrind_output and "0 bytes" not in valgrind_output:
                    performance_summary["memory_leaks"] = True
                    self.report_data["recommendations"].append(
                        "🚨 Memory leaks detected - review valgrind output"
                    )
                
            except FileNotFoundError as e:
                print(f"⚠️ Error reading valgrind file {valgrind_file}: {e}")
        
        self.report_data["performance_metrics"] = performance_summary

    def analyze_documentation_status(self) -> None:
        """Analyze documentation generation and validation results"""
        print("📚 Analyzing documentation status...")
        
        doc_summary = {
            "api_docs_generated": False,
            "architecture_diagrams_updated": False,
            "book_built": False,
            "broken_links": 0,
            "coverage_percentage": 0
        }
        
        # Check for generated documentation
        doc_paths = {
            "api_docs": self.artifacts_dir / "target" / "doc",
            "diagrams": self.artifacts_dir / "docs" / "architecture",
            "book": self.artifacts_dir / "docs" / "book"
        }
        
        doc_summary["api_docs_generated"] = doc_paths["api_docs"].exists()
        doc_summary["architecture_diagrams_updated"] = (
            doc_paths["diagrams"].exists() and 
            len(list(doc_paths["diagrams"].glob("*.pdf"))) > 0
        )
        doc_summary["book_built"] = doc_paths["book"].exists()
        
        # Check for broken links (would be in CI logs)
        # This is a simplified check - in practice, would parse CI logs
        
        self.report_data["documentation_status"] = doc_summary
        
        if not doc_summary["api_docs_generated"]:
            self.report_data["recommendations"].append(
                "📚 API documentation generation failed - check build logs"
            )

    def calculate_overall_score(self) -> float:
        """Calculate overall health score (0-100)"""
        score = 100.0
        
        # Hardware test success rate (40% weight)
        hardware_tests = self.report_data["hardware_tests"]["configurations"]
        total_tests = sum(config["total"] for config in hardware_tests.values())
        passed_tests = sum(config["passed"] for config in hardware_tests.values())
        
        if total_tests > 0:
            hardware_score = (passed_tests / total_tests) * 40
        else:
            hardware_score = 0
        
        # Security score (30% weight)
        security = self.report_data["security_analysis"]
        security_score = 30
        
        # Deduct points for vulnerabilities
        security_score -= security["vulnerabilities"]["high"] * 10
        security_score -= security["vulnerabilities"]["medium"] * 5
        security_score -= security["vulnerabilities"]["low"] * 1
        security_score -= security["dependency_issues"] * 2
        
        security_score = max(0, security_score)
        
        # Documentation score (20% weight)
        docs = self.report_data["documentation_status"]
        doc_score = 0
        if docs["api_docs_generated"]:
            doc_score += 7
        if docs["architecture_diagrams_updated"]:
            doc_score += 7
        if docs["book_built"]:
            doc_score += 6
        
        # Performance score (10% weight)
        perf = self.report_data["performance_metrics"]
        perf_score = 10
        if perf["memory_leaks"]:
            perf_score -= 5
        
        total_score = hardware_score + security_score + doc_score + perf_score
        return min(100, max(0, total_score))

    def generate_summary(self) -> None:
        """Generate executive summary"""
        overall_score = self.calculate_overall_score()
        
        # Determine health status
        if overall_score >= 90:
            status = "🟢 Excellent"
        elif overall_score >= 75:
            status = "🟡 Good"
        elif overall_score >= 60:
            status = "🟠 Fair"
        else:
            status = "🔴 Poor"
        
        self.report_data["summary"] = {
            "overall_score": overall_score,
            "health_status": status,
            "total_recommendations": len(self.report_data["recommendations"]),
            "critical_issues": len([r for r in self.report_data["recommendations"] if "🚨" in r])
        }

    def generate_html_report(self, output_file: str = "test_report.html") -> None:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Universal AI Governor - Test Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .score {{ font-size: 3em; font-weight: bold; margin: 20px 0; }}
        .status {{ font-size: 1.5em; margin: 10px 0; }}
        .section {{ margin: 30px 0; padding: 20px; border-left: 4px solid #007acc; background: #f8f9fa; }}
        .section h2 {{ margin-top: 0; color: #007acc; }}
        .metric {{ display: inline-block; margin: 10px 20px; padding: 15px; background: white; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .recommendations {{ background: #fff3cd; border-left-color: #ffc107; }}
        .recommendations ul {{ margin: 0; padding-left: 20px; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: 600; }}
        .success {{ color: #28a745; }}
        .warning {{ color: #ffc107; }}
        .danger {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Universal AI Governor</h1>
            <h2>Hardware Integration Test Report</h2>
            <div class="timestamp">Generated: {timestamp}</div>
            <div class="score">{overall_score:.1f}/100</div>
            <div class="status">{health_status}</div>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="metric">
                <strong>Overall Score:</strong> {overall_score:.1f}/100
            </div>
            <div class="metric">
                <strong>Health Status:</strong> {health_status}
            </div>
            <div class="metric">
                <strong>Total Recommendations:</strong> {total_recommendations}
            </div>
            <div class="metric">
                <strong>Critical Issues:</strong> {critical_issues}
            </div>
        </div>

        <div class="section">
            <h2>🔧 Hardware Test Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Configuration</th>
                        <th>Total Tests</th>
                        <th>Passed</th>
                        <th>Failed</th>
                        <th>Success Rate</th>
                    </tr>
                </thead>
                <tbody>
                    {hardware_test_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>🔒 Security Analysis</h2>
            <div class="metric">
                <strong>High Severity:</strong> <span class="danger">{high_vulns}</span>
            </div>
            <div class="metric">
                <strong>Medium Severity:</strong> <span class="warning">{medium_vulns}</span>
            </div>
            <div class="metric">
                <strong>Low Severity:</strong> {low_vulns}
            </div>
            <div class="metric">
                <strong>Dependency Issues:</strong> {dep_issues}
            </div>
            <div class="metric">
                <strong>Unsafe Code Blocks:</strong> {unsafe_blocks}
            </div>
        </div>

        <div class="section">
            <h2>⚡ Performance Metrics</h2>
            <div class="metric">
                <strong>Benchmarks Run:</strong> {benchmark_count}
            </div>
            <div class="metric">
                <strong>Memory Leaks:</strong> <span class="{leak_class}">{memory_leaks}</span>
            </div>
        </div>

        <div class="section">
            <h2>📚 Documentation Status</h2>
            <div class="metric">
                <strong>API Docs:</strong> <span class="{api_docs_class}">{api_docs_status}</span>
            </div>
            <div class="metric">
                <strong>Architecture Diagrams:</strong> <span class="{diagrams_class}">{diagrams_status}</span>
            </div>
            <div class="metric">
                <strong>Documentation Book:</strong> <span class="{book_class}">{book_status}</span>
            </div>
        </div>

        {recommendations_section}
    </div>
</body>
</html>
        """
        
        # Prepare hardware test rows
        hardware_rows = []
        for config, results in self.report_data["hardware_tests"]["configurations"].items():
            if results["total"] > 0:
                success_rate = (results["passed"] / results["total"]) * 100
                success_class = "success" if success_rate >= 90 else "warning" if success_rate >= 75 else "danger"
                hardware_rows.append(f"""
                    <tr>
                        <td>{config.replace('-', ' ').title()}</td>
                        <td>{results["total"]}</td>
                        <td class="success">{results["passed"]}</td>
                        <td class="danger">{results["failed"]}</td>
                        <td class="{success_class}">{success_rate:.1f}%</td>
                    </tr>
                """)
        
        # Prepare recommendations section
        recommendations_html = ""
        if self.report_data["recommendations"]:
            recommendations_html = f"""
            <div class="section recommendations">
                <h2>💡 Recommendations</h2>
                <ul>
                    {"".join(f"<li>{rec}</li>" for rec in self.report_data["recommendations"])}
                </ul>
            </div>
            """
        
        # Format the HTML
        security = self.report_data["security_analysis"]
        docs = self.report_data["documentation_status"]
        perf = self.report_data["performance_metrics"]
        summary = self.report_data["summary"]
        
        html_content = html_template.format(
            timestamp=self.report_data["timestamp"],
            overall_score=summary["overall_score"],
            health_status=summary["health_status"],
            total_recommendations=summary["total_recommendations"],
            critical_issues=summary["critical_issues"],
            hardware_test_rows="".join(hardware_rows),
            high_vulns=security["vulnerabilities"]["high"],
            medium_vulns=security["vulnerabilities"]["medium"],
            low_vulns=security["vulnerabilities"]["low"],
            dep_issues=security["dependency_issues"],
            unsafe_blocks=security["unsafe_code_blocks"],
            benchmark_count=len(perf["benchmarks"]),
            memory_leaks="Yes" if perf["memory_leaks"] else "No",
            leak_class="danger" if perf["memory_leaks"] else "success",
            api_docs_status="Generated" if docs["api_docs_generated"] else "Failed",
            api_docs_class="success" if docs["api_docs_generated"] else "danger",
            diagrams_status="Updated" if docs["architecture_diagrams_updated"] else "Failed",
            diagrams_class="success" if docs["architecture_diagrams_updated"] else "danger",
            book_status="Built" if docs["book_built"] else "Failed",
            book_class="success" if docs["book_built"] else "danger",
            recommendations_section=recommendations_html
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"📄 HTML report generated: {output_file}")

    def generate_json_report(self, output_file: str = "test_report.json") -> None:
        """Generate JSON report for programmatic consumption"""
        with open(output_file, 'w') as f:
            json.dump(self.report_data, f, indent=2)
        
        print(f"📄 JSON report generated: {output_file}")

    def generate_markdown_summary(self, output_file: str = "TEST_SUMMARY.md") -> None:
        """Generate markdown summary for GitHub"""
        summary = self.report_data["summary"]
        
        markdown_content = f"""# 🛡️ Universal AI Governor - Test Summary

**Generated:** {self.report_data["timestamp"]}

## 📊 Overall Health: {summary["health_status"]} ({summary["overall_score"]:.1f}/100)

### 🔧 Hardware Integration Tests
"""
        
        for config, results in self.report_data["hardware_tests"]["configurations"].items():
            if results["total"] > 0:
                success_rate = (results["passed"] / results["total"]) * 100
                status_emoji = "✅" if success_rate >= 90 else "⚠️" if success_rate >= 75 else "❌"
                markdown_content += f"- {status_emoji} **{config.replace('-', ' ').title()}**: {results['passed']}/{results['total']} ({success_rate:.1f}%)\n"
        
        security = self.report_data["security_analysis"]
        total_vulns = sum(security["vulnerabilities"].values())
        
        markdown_content += f"""
### 🔒 Security Analysis
- **Vulnerabilities**: {total_vulns} total ({security["vulnerabilities"]["high"]} high, {security["vulnerabilities"]["medium"]} medium, {security["vulnerabilities"]["low"]} low)
- **Dependency Issues**: {security["dependency_issues"]}
- **Unsafe Code Blocks**: {security["unsafe_code_blocks"]}

### 📚 Documentation Status
- **API Documentation**: {"✅ Generated" if self.report_data["documentation_status"]["api_docs_generated"] else "❌ Failed"}
- **Architecture Diagrams**: {"✅ Updated" if self.report_data["documentation_status"]["architecture_diagrams_updated"] else "❌ Failed"}
- **Documentation Book**: {"✅ Built" if self.report_data["documentation_status"]["book_built"] else "❌ Failed"}

### ⚡ Performance
- **Benchmarks**: {len(self.report_data["performance_metrics"]["benchmarks"])} executed
- **Memory Leaks**: {"❌ Detected" if self.report_data["performance_metrics"]["memory_leaks"] else "✅ None"}
"""
        
        if self.report_data["recommendations"]:
            markdown_content += "\n### 💡 Recommendations\n"
            for rec in self.report_data["recommendations"]:
                markdown_content += f"- {rec}\n"
        
        with open(output_file, 'w') as f:
            f.write(markdown_content)
        
        print(f"📄 Markdown summary generated: {output_file}")

    def run_analysis(self) -> None:
        """Run complete analysis and generate reports"""
        print("🚀 Starting comprehensive test analysis...")
        
        self.analyze_hardware_tests()
        self.analyze_security_results()
        self.analyze_performance_metrics()
        self.analyze_documentation_status()
        self.generate_summary()
        
        print(f"\n📊 Analysis Complete!")
        print(f"Overall Score: {self.report_data['summary']['overall_score']:.1f}/100")
        print(f"Health Status: {self.report_data['summary']['health_status']}")
        print(f"Recommendations: {self.report_data['summary']['total_recommendations']}")
        
        # Generate all report formats
        self.generate_html_report()
        self.generate_json_report()
        self.generate_markdown_summary()

def main():
    parser = argparse.ArgumentParser(description="Generate comprehensive test reports")
    parser.add_argument("--artifacts-dir", default=".", help="Directory containing test artifacts")
    parser.add_argument("--output-dir", default=".", help="Directory for output reports")
    parser.add_argument("--format", choices=["html", "json", "markdown", "all"], default="all", help="Report format")
    
    args = parser.parse_args()
    
    # Change to output directory
    if args.output_dir != ".":
        os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)
    
    generator = TestReportGenerator(args.artifacts_dir)
    generator.run_analysis()
    
    print("\n✅ Test report generation completed successfully!")

if __name__ == "__main__":
    main()
