# report_generator.py
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import datetime

def generate_pdf_report(url, results, filename):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#667eea'),
        spaceAfter=30
    )
    story.append(Paragraph(f"Vulnerability Scan Report", title_style))
    story.append(Spacer(1, 12))
    
    # Info
    story.append(Paragraph(f"<b>URL:</b> {url}", styles['Normal']))
    story.append(Paragraph(f"<b>Scan Date:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Paragraph(f"<b>Security Score:</b> {results['security_score']}/100", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Vulnerabilities
    story.append(Paragraph("<b>Detected Vulnerabilities:</b>", styles['Heading2']))
    for vuln in results['vulnerabilities']:
        story.append(Paragraph(f"• {vuln['type']} <font color='red'>({vuln['severity'].upper()})</font>", styles['Normal']))
    
    doc.build(story)
    return filename