from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

def generate_report(attacks):

    doc = SimpleDocTemplate("incident_report.pdf")
    styles = getSampleStyleSheet()

    flow = []

    flow.append(
        Paragraph("Cyber Incident Report",
        styles["Title"])
    )

    for a in attacks:
        flow.append(
            Paragraph(f"Attack detected: {a}",
            styles["Normal"])
        )

    doc.build(flow)