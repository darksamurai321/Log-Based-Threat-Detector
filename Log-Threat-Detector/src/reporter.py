from fpdf import FPDF
import datetime
import os

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'SENTINYL - Security Threat Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(alerts_data):
    """
    Generates a PDF audit report with remediation steps.
    """
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # 1. Report Metadata
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pdf.cell(0, 10, txt=f"Scan Date: {timestamp}", ln=True)
    pdf.cell(0, 10, txt=f"Total Incidents: {len(alerts_data)}", ln=True)
    pdf.ln(5)

    # 2. Incident Table Header
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(200, 220, 255) # Light Blue
    
    # Column Widths
    w_ip = 35
    w_type = 70
    w_time = 45
    w_action = 40

    pdf.cell(w_ip, 8, "Attacker IP", 1, 0, 'C', 1)
    pdf.cell(w_type, 8, "Threat Classification", 1, 0, 'C', 1)
    pdf.cell(w_time, 8, "Timestamp", 1, 0, 'C', 1)
    pdf.cell(w_action, 8, "System Action", 1, 1, 'C', 1)

    # 3. Table Data
    pdf.set_font("Arial", size=9)
    for alert in alerts_data:
        # Determine Status
        status = "Logged"
        if "SQL" in alert['Threat Type'] or "KNOWN" in alert['Threat Type']:
            status = "Auto-Blocked"
        
        # Safe string slicing to fit PDF columns
        t_type = alert['Threat Type'][:35] 
        
        pdf.cell(w_ip, 8, alert['Attacker IP'], 1)
        pdf.cell(w_type, 8, t_type, 1)
        pdf.cell(w_time, 8, alert['Timestamp'], 1)
        pdf.cell(w_action, 8, status, 1, 1)

    # 4. Remediation Section (Client Requirement)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Remediation Recommendations", ln=True)
    pdf.set_font("Arial", size=10)
    
    recommendations = [
        "- Update Firewall Rules: Permanently block the IPs listed above.",
        "- Patching: Ensure the web server is patched against identified vulnerabilities (SQLi/XSS).",
        "- Input Validation: Review code to sanitize inputs triggering 'Double Encoding'.",
        "- Credential Rotation: Reset passwords for any accounts involved in Brute Force attempts."
    ]
    
    for rec in recommendations:
        pdf.cell(0, 8, rec, ln=True)

    # 5. Save File
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    filename = f"reports/Threat_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    return os.path.abspath(filename)