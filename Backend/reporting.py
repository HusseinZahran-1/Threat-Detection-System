# reporting.py
import os
import json
from datetime import datetime
from fpdf import FPDF
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from io import BytesIO
import base64

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_enhanced_report(self, report_data, report_type="summary"):
        """Generate enhanced PDF threat report"""
        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            
            # Add cover page
            self._add_cover_page(pdf, report_type)
            
            # Add summary section
            self._add_summary_section(pdf, report_data)
            
            # Add detailed findings based on report type
            if report_type == "detailed":
                self._add_detailed_findings(pdf, report_data)
            
            # Add threat intelligence section
            self._add_threat_intelligence(pdf, report_data)
            
            # Add recommendations
            self._add_recommendations(pdf, report_data)
            
            # Generate filename and save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_report_{report_type}_{timestamp}.pdf"
            filepath = os.path.join(self.output_dir, filename)
            
            pdf.output(filepath)
            print(f"✅ Report generated: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"❌ Report generation error: {e}")
            # Fallback to simple report
            return self._generate_simple_report(report_data, report_type)
    
    def _add_cover_page(self, pdf, report_type):
        """Add cover page to PDF"""
        pdf.add_page()
        pdf.set_font("Arial", "B", 24)
        pdf.cell(0, 60, "THREAT DETECTION REPORT", 0, 1, "C")
        pdf.set_font("Arial", "I", 16)
        pdf.cell(0, 20, f"Report Type: {report_type.title()}", 0, 1, "C")
        pdf.cell(0, 20, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "C")
        pdf.ln(20)
        
    def _add_summary_section(self, pdf, report_data):
        """Add summary section to PDF"""
        pdf.add_page()
        pdf.set_font("Arial", "B", 18)
        pdf.cell(0, 10, "Executive Summary", 0, 1)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        
        # Extract summary statistics
        total_analyzed = report_data.get('total_analyzed', 0)
        threats_detected = report_data.get('threats_detected', 0)
        avg_confidence = report_data.get('average_confidence', 0)
        
        summary_text = f"""
        Total Logs Analyzed: {total_analyzed}
        Threats Detected: {threats_detected}
        Threat Detection Rate: {(threats_detected/total_analyzed*100) if total_analyzed > 0 else 0:.2f}%
        Average Confidence: {avg_confidence:.2f}
        
        This report provides a comprehensive analysis of security threats detected
        by the Enhanced Threat Detection System. The system employs multi-layered
        detection including machine learning, behavioral analysis, and threat
        intelligence to identify potential security incidents.
        """
        
        pdf.multi_cell(0, 8, summary_text)
        
    def _add_detailed_findings(self, pdf, report_data):
        """Add detailed findings section"""
        pdf.add_page()
        pdf.set_font("Arial", "B", 18)
        pdf.cell(0, 10, "Detailed Findings", 0, 1)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 10)
        
        # Add table headers
        headers = ["Threat ID", "Source IP", "Confidence", "Type", "Timestamp"]
        col_widths = [30, 40, 30, 50, 40]
        
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 10, header, 1, 0, "C")
        pdf.ln()
        
        # Add threat data rows
        threats = report_data.get('threats', [])
        for threat in threats[:20]:  # Limit to first 20 threats
            pdf.cell(col_widths[0], 10, str(threat.get('id', 'N/A')), 1)
            pdf.cell(col_widths[1], 10, threat.get('source_ip', 'Unknown'), 1)
            pdf.cell(col_widths[2], 10, f"{threat.get('confidence', 0):.2f}", 1)
            pdf.cell(col_widths[3], 10, threat.get('threat_type', 'Unknown'), 1)
            pdf.cell(col_widths[4], 10, threat.get('timestamp', 'N/A')[:16], 1)
            pdf.ln()
            
    def _add_threat_intelligence(self, pdf, report_data):
        """Add threat intelligence section"""
        pdf.add_page()
        pdf.set_font("Arial", "B", 18)
        pdf.cell(0, 10, "Threat Intelligence", 0, 1)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        
        intel_data = report_data.get('threat_intelligence', {})
        if intel_data:
            intel_text = f"""
            Global Threat Level: {intel_data.get('global_threat_level', 'Unknown')}
            High-Risk IPs Detected: {intel_data.get('high_risk_ips', 0)}
            Recent Malware Families: {', '.join(intel_data.get('malware_families', []))}
            
            The threat intelligence data is sourced from global threat feeds and
            provides context for the detected security incidents.
            """
        else:
            intel_text = "No threat intelligence data available for this report period."
            
        pdf.multi_cell(0, 8, intel_text)
        
    def _add_recommendations(self, pdf, report_data):
        """Add security recommendations"""
        pdf.add_page()
        pdf.set_font("Arial", "B", 18)
        pdf.cell(0, 10, "Security Recommendations", 0, 1)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        
        recommendations = [
            "1. Review and investigate all high-confidence threats immediately",
            "2. Block identified malicious IP addresses at the firewall level",
            "3. Update security signatures and threat intelligence feeds",
            "4. Conduct security awareness training for identified attack patterns",
            "5. Review and update access control policies",
            "6. Implement additional monitoring for suspicious user behavior",
            "7. Schedule regular security audits and penetration testing"
        ]
        
        for recommendation in recommendations:
            pdf.multi_cell(0, 8, recommendation)
            pdf.ln(2)
            
    def _generate_simple_report(self, report_data, report_type):
        """Generate a simple text report as fallback"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"simple_report_{report_type}_{timestamp}.txt"
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write("THREAT DETECTION REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write(f"Report Type: {report_type}\n\n")
                f.write(f"Total Analyzed: {report_data.get('total_analyzed', 0)}\n")
                f.write(f"Threats Detected: {report_data.get('threats_detected', 0)}\n")
                f.write(f"Average Confidence: {report_data.get('average_confidence', 0):.2f}\n")
                
            return filepath
        except Exception as e:
            print(f"❌ Simple report generation failed: {e}")
            return None

    def generate_dashboard_report(self, dashboard_data):
        """Generate a report from dashboard data"""
        return self.generate_enhanced_report(dashboard_data, "dashboard")

# Global instance
report_generator = ReportGenerator()