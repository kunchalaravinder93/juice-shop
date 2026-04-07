import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime

# --- Configuration ---
REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")
OUTPUT_FILE = os.path.join(REPORTS_DIR, "dashboard.html")

def load_json(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
    return None

def parse_npm_audit_detailed(filename):
    path = os.path.join(REPORTS_DIR, filename)
    sca_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "findings": []}
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                
                if "metadata" in data and "vulnerabilities" in data["metadata"]:
                    vulns = data["metadata"]["vulnerabilities"]
                    sca_summary["critical"] = vulns.get("critical", 0)
                    sca_summary["high"] = vulns.get("high", 0)
                    sca_summary["medium"] = vulns.get("moderate", 0)
                    sca_summary["low"] = vulns.get("low", 0)
                    sca_summary["total"] = vulns.get("total", 0)
                
                # Extract detailed findings (vulnerabilities list in npm 7+)
                if "vulnerabilities" in data:
                    for pkg, details in data["vulnerabilities"].items():
                        sca_summary["findings"].append({
                            "package": pkg,
                            "severity": details.get("severity", "unknown").upper(),
                            "fix": details.get("fixAvailable", "Manual Update Required")
                        })
        except Exception as e:
            print(f"Error parsing {filename}: {e}")
    return sca_summary

def parse_zap_detailed(filename):
    data = load_json(filename)
    zap_summary = {"total": 0, "high": 0, "medium": 0, "low": 0, "informational": 0, "findings": []}
    if data and "site" in data:
        for site in data["site"]:
            for alert in site.get("alerts", []):
                zap_summary["total"] += 1
                risk = alert.get("riskdesc", "").split(" (")[0]
                if risk == "High": zap_summary["high"] += 1
                elif risk == "Medium": zap_summary["medium"] += 1
                elif risk == "Low": zap_summary["low"] += 1
                elif risk == "Informational": zap_summary["informational"] += 1
                
                instances = [inst.get("uri", "") for inst in alert.get("instances", [])]
                zap_summary["findings"].append({
                    "name": alert.get("alert", "N/A"),
                    "risk": risk.upper(),
                    "solution": alert.get("solution", "N/A"),
                    "instances": instances[:5] # Top 5 URLs
                })
    return zap_summary

def parse_jmeter_detailed(filename):
    path = os.path.join(REPORTS_DIR, filename)
    perf_summary = {"samples": 0, "errors": 0, "avg_rt": 0, "max_rt": 0, "endpoints": {}}
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                lines = f.readlines()[1:] # Skip header
                if lines:
                    rts = []
                    for line in lines:
                        parts = line.split(",")
                        if len(parts) >= 8:
                            label = parts[2]
                            rt = int(parts[1])
                            success = parts[7] == "true"
                            
                            perf_summary["samples"] += 1
                            rts.append(rt)
                            if not success: perf_summary["errors"] += 1
                            
                            if label not in perf_summary["endpoints"]:
                                perf_summary["endpoints"][label] = {"count": 0, "total_rt": 0, "errors": 0, "min": rt, "max": rt}
                            
                            e = perf_summary["endpoints"][label]
                            e["count"] += 1
                            e["total_rt"] += rt
                            e["min"] = min(e["min"], rt)
                            e["max"] = max(e["max"], rt)
                            if not success: e["errors"] += 1

                    if rts:
                        perf_summary["avg_rt"] = sum(rts) / len(rts)
                        perf_summary["max_rt"] = max(rts)
        except Exception as e:
            print(f"Error parsing {filename}: {e}")
    return perf_summary

def generate_dashboard():
    # 1. Parse all results with full detail
    sca = parse_npm_audit_detailed("npm-audit.json")
    zap = parse_zap_detailed("zap-report.json")
    perf = parse_jmeter_detailed("jmeter-results.jtl")
    sonar_summary = load_json("sonar-summary.json") or {"critical": 0, "major": 0}
    sonar_issues = load_json("sonar-issues.json") or {"issues": []}

    # 2. Risk Scoring
    score = 100
    score -= (sca["critical"] * 10 + sca["high"] * 5)
    score -= (sonar_summary["critical"] * 10 + sonar_summary["major"] * 3)
    score -= (zap["high"] * 15 + zap["medium"] * 5)
    score = max(0, score)
    
    grade = "A" if score > 90 else "B" if score > 75 else "C" if score > 50 else "D" if score > 25 else "F"
    color = "#34d399" if grade == "A" else "#fbbf24" if grade in ["B", "C"] else "#fb7185"

    # 3. Build HTML with INLINE STYLES for Jenkins CSP compatibility
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Pre-calculate UI blocks
    sonar_rows = "".join([f'<tr><td style="padding:12px; border-bottom:1px solid #334155;">{i.get("message","N/A")}</td><td style="padding:12px; border-bottom:1px solid #334155; font-family:monospace; font-size:0.85em; color:#94a3b8;">{i.get("component","N/A").split(":")[-1]}</td></tr>' for i in sonar_issues.get("issues", [])])
    sca_rows = "".join([f'<tr><td style="padding:12px; border-bottom:1px solid #334155;">{f["package"]}</td><td style="padding:12px; border-bottom:1px solid #334155;"><span style="color:{"#fb7185" if f["severity"]=="CRITICAL" else "#f97316"}; font-weight:bold;">{f["severity"]}</span></td><td style="padding:12px; border-bottom:1px solid #334155; color:#94a3b8;">{f["fix"]}</td></tr>' for f in sca["findings"][:20]])
    zap_rows = "".join([f'<tr><td style="padding:12px; border-bottom:1px solid #334155; font-weight:bold;">{f["name"]}</td><td style="padding:12px; border-bottom:1px solid #334155; color:{"#fb7185" if f["risk"]=="HIGH" else "#f97316"};">{f["risk"]}</td><td style="padding:12px; border-bottom:1px solid #334155; font-size:0.9em;">{f["solution"]}</td></tr>' for f in zap["findings"]])
    perf_rows = "".join([f'<tr><td style="padding:12px; border-bottom:1px solid #334155; font-family:monospace; font-size:0.85em;">{k}</td><td style="padding:12px; border-bottom:1px solid #334155;">{v["count"]}</td><td style="padding:12px; border-bottom:1px solid #334155;">{int(v["total_rt"]/v["count"])}ms</td><td style="padding:12px; border-bottom:1px solid #334155; color:{"#fb7185" if v["errors"]>0 else "#34d399"};">{v["errors"]}</td></tr>' for k,v in perf.get("endpoints", {}).items()])

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <body style="background-color: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0;">
        <div style="display: flex; min-height: 100vh;">
            <!-- SIDEBAR -->
            <div style="width: 260px; background-color: #1e293b; border-right: 1px solid #334155; padding: 30px 20px; position: fixed; height: 100vh;">
                <h2 style="color: #22d3ee; margin-top: 0; font-size: 1.4rem; letter-spacing: -0.02em;">🛡️ SHIVA AI</h2>
                <div style="margin-top: 40px;">
                    <a href="#overview" style="display: block; color: #cbd5e1; text-decoration: none; padding: 12px 0; font-weight: 500;">📊 Executive Overview</a>
                    <a href="#sast" style="display: block; color: #cbd5e1; text-decoration: none; padding: 12px 0; font-weight: 500;">🔍 SAST (Sonar)</a>
                    <a href="#sca" style="display: block; color: #cbd5e1; text-decoration: none; padding: 12px 0; font-weight: 500;">📦 SCA (Dependencies)</a>
                    <a href="#dast" style="display: block; color: #cbd5e1; text-decoration: none; padding: 12px 0; font-weight: 500;">🕷️ DAST (ZAP Full)</a>
                    <a href="#perf" style="display: block; color: #cbd5e1; text-decoration: none; padding: 12px 0; font-weight: 500;">⚡ Performance</a>
                </div>
                <div style="position: absolute; bottom: 30px; font-size: 0.8rem; color: #64748b;">
                    v3.0 PRO ENHANCED<br>Generated: {now}
                </div>
            </div>

            <!-- MAIN CONTENT -->
            <div style="margin-left: 260px; padding: 60px; width: 100%;">
                <div id="overview" style="margin-bottom: 60px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px;">
                        <div>
                            <h1 style="margin: 0; font-size: 2.5rem; font-weight: 800; background: linear-gradient(90deg, #22d3ee, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Security Intelligence Hub</h1>
                            <p style="color: #94a3b8; margin-top: 8px;">Full Audit Report for OWASP Juice Shop | Target: 65.1.109.17</p>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 0.9rem; color: #94a3b8; margin-bottom: 4px;">SECURITY GRADE</div>
                            <div style="font-size: 3.5rem; font-weight: 900; color: {color}; line-height: 1;">{grade}</div>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px;">
                        <div style="background: #1e293b; padding: 24px; border-radius: 16px; border: 1px solid #334155;">
                            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase;">Sonar Issues</div>
                            <div style="font-size: 2rem; font-weight: 700; margin-top: 10px;">{sonar_summary['critical']} Critical</div>
                        </div>
                        <div style="background: #1e293b; padding: 24px; border-radius: 16px; border: 1px solid #334155;">
                            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase;">SCA Vulns</div>
                            <div style="font-size: 2rem; font-weight: 700; margin-top: 10px;">{sca['total']} Total</div>
                        </div>
                        <div style="background: #1e293b; padding: 24px; border-radius: 16px; border: 1px solid #334155;">
                            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase;">ZAP Alerts</div>
                            <div style="font-size: 2rem; font-weight: 700; margin-top: 10px;">{zap['high']} High</div>
                        </div>
                        <div style="background: #1e293b; padding: 24px; border-radius: 16px; border: 1px solid #334155;">
                            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase;">Average RT</div>
                            <div style="font-size: 2rem; font-weight: 700; margin-top: 10px;">{int(perf['avg_rt'])}ms</div>
                        </div>
                    </div>
                </div>

                <!-- SAST SECTION -->
                <div id="sast" style="margin-bottom: 80px; scroll-margin-top: 40px;">
                    <h2 style="border-left: 4px solid #818cf8; padding-left: 15px; margin-bottom: 30px;">🔍 SAST: Full Code Finding Registry</h2>
                    <div style="background: #1e293b; border-radius: 16px; overflow: hidden; border: 1px solid #334155;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left;">
                            <thead style="background: #0f172a;">
                                <tr><th style="padding:15px; color:#94a3b8;">Issue Message</th><th style="padding:15px; color:#94a3b8;">Component / File</th></tr>
                            </thead>
                            <tbody>{sonar_rows or '<tr><td colspan="2" style="padding:20px; text-align:center; color:#64748b;">No security issues found by SonarQube</td></tr>'}</tbody>
                        </table>
                    </div>
                </div>

                <!-- SCA SECTION -->
                <div id="sca" style="margin-bottom: 80px; scroll-margin-top: 40px;">
                    <h2 style="border-left: 4px solid #f97316; padding-left: 15px; margin-bottom: 30px;">📦 SCA: Detailed Dependency Audit</h2>
                    <div style="background: #1e293b; border-radius: 16px; overflow: hidden; border: 1px solid #334155;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left;">
                            <thead style="background: #0f172a;">
                                <tr><th style="padding:15px; color:#94a3b8;">Package</th><th style="padding:15px; color:#94a3b8;">Severity</th><th style="padding:15px; color:#94a3b8;">Recommended Action</th></tr>
                            </thead>
                            <tbody>{sca_rows or '<tr><td colspan="3" style="padding:20px; text-align:center; color:#64748b;">No dependency vulnerabilities found</td></tr>'}</tbody>
                        </table>
                    </div>
                </div>

                <!-- DAST SECTION -->
                <div id="dast" style="margin-bottom: 80px; scroll-margin-top: 40px;">
                    <h2 style="border-left: 4px solid #fb7185; padding-left: 15px; margin-bottom: 30px;">🕷️ DAST: Full Penetration Test Results</h2>
                    <div style="background: #1e293b; border-radius: 16px; overflow: hidden; border: 1px solid #334155;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left;">
                            <thead style="background: #0f172a;">
                                <tr><th style="padding:15px; color:#94a3b8;">Alert Type</th><th style="padding:15px; color:#94a3b8;">Risk</th><th style="padding:15px; color:#94a3b8;">Expert Remediation</th></tr>
                            </thead>
                            <tbody>{zap_rows or '<tr><td colspan="3" style="padding:20px; text-align:center; color:#64748b;">No active scan alerts reported by ZAP</td></tr>'}</tbody>
                        </table>
                    </div>
                </div>

                <!-- PERFORMANCE SECTION -->
                <div id="perf" style="margin-bottom: 80px; scroll-margin-top: 40px;">
                    <h2 style="border-left: 4px solid #22d3ee; padding-left: 15px; margin-bottom: 30px;">⚡ Performance: Global Endpoint Metrics</h2>
                    <div style="background: #1e293b; border-radius: 16px; overflow: hidden; border: 1px solid #334155;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left;">
                            <thead style="background: #0f172a;">
                                <tr><th style="padding:15px; color:#94a3b8;">Endpoint Path</th><th style="padding:15px; color:#94a3b8;">Samples</th><th style="padding:15px; color:#94a3b8;">Avg Latency</th><th style="padding:15px; color:#94a3b8;">Error Count</th></tr>
                            </thead>
                            <tbody>{perf_rows or '<tr><td colspan="4" style="padding:20px; text-align:center; color:#64748b;">No JMeter results available</td></tr>'}</tbody>
                        </table>
                    </div>
                </div>

                <div style="border-top: 1px solid #334155; padding-top: 40px; text-align: center; color: #475569; font-size: 0.9rem;">
                    SHIVA AI Cyber-Security Intelligence Suite &copy; 2026 | Automated DevSecOps Pipeline
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(OUTPUT_FILE, "w") as f:
        f.write(html_content)
    print(f"Professional Dashboard generated at: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_dashboard()
