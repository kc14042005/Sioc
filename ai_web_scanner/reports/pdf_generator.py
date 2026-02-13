from typing import List, Dict
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os

class PDFReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#16213e'),
            spaceAfter=12,
            spaceBefore=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=11,
            textColor=colors.HexColor('#0f3460'),
            spaceAfter=6
        ))
    
    def generate_report(self, scan_data: Dict, vulnerabilities: List[Dict], 
                       ai_analysis: Dict, output_path: str) -> str:
        """Generate PDF vulnerability report"""
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=LETTER,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Title
        story.append(Paragraph("Web Vulnerability Scan Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Scan Summary Table
        scan_date = scan_data.get('created_at') or scan_data.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        scan_score = scan_data.get('score', scan_data.get('risk_score', 0))
        
        scan_info = [
            ['Target URL', scan_data.get('url', 'N/A')],
            ['Scan Date', scan_date],
            ['Security Score', f"{scan_score:.1f} / 100"],
            ['Risk Level', ai_analysis.get('risk_level', 'Unknown')],
            ['Vulnerabilities Found', str(len(vulnerabilities))]
        ]
        
        scan_table = Table(scan_info, colWidths=[2*inch, 4*inch])
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f5')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a1a2e')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        story.append(scan_table)
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        exec_summary = ai_analysis.get('executive_summary', 'No summary available.')
        story.append(Paragraph(exec_summary, self.styles['BodyText']))
        story.append(Spacer(1, 20))
        
        # Risk Assessment
        story.append(Paragraph("Risk Assessment", self.styles['SectionHeader']))
        story.append(Paragraph(ai_analysis.get('summary', 'No analysis available.'), self.styles['BodyText']))
        story.append(Spacer(1, 20))
        
        # Vulnerabilities Section
        if vulnerabilities:
            story.append(Paragraph("Vulnerabilities Found", self.styles['SectionHeader']))
            
            for i, vuln in enumerate(vulnerabilities, 1):
                story.append(Paragraph(
                    f"{i}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')} Severity",
                    self.styles['VulnTitle']
                ))
                
                vuln_details = [
                    ['Description', vuln.get('description', 'N/A')],
                    ['Severity', vuln.get('severity', 'Unknown')],
                    ['Remediation', vuln.get('remediation', 'N/A')]
                ]
                
                vuln_table = Table(vuln_details, colWidths=[1.5*inch, 4.5*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8e8f0')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 15))
        
        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        recommendations = ai_analysis.get('recommendations', [])
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", self.styles['BodyText']))
                story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("No specific recommendations available.", self.styles['BodyText']))
        
        story.append(Spacer(1, 30))
        
        # Footer
        story.append(Paragraph(
            f"Report generated by AI-Powered Web Vulnerability Scanner on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['BodyText']
        ))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    def generate_summary_report(self, scan_history: List[Dict], output_path: str) -> str:
        """Generate summary report of multiple scans"""
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=LETTER,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Title
        story.append(Paragraph("Scan History Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Summary Stats
        total_scans = len(scan_history)
        avg_risk = sum(s.get('risk_score', 0) for s in scan_history) / total_scans if total_scans > 0 else 0
        
        stats_data = [
            ['Total Scans', str(total_scans)],
            ['Average Risk Score', f"{avg_risk:.2f}"],
            ['Date Range', f"{scan_history[0].get('date', 'N/A') if scan_history else 'N/A'}"]
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 4*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f5')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a1a2e')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 30))
        
        # Scan History Table
        story.append(Paragraph("Scan History", self.styles['SectionHeader']))
        
        table_data = [['Date', 'URL', 'Risk Score', 'Vulns']]
        
        for scan in scan_history[:20]:  # Limit to 20 most recent
            table_data.append([
                scan.get('date', 'N/A')[:10],
                scan.get('url', 'N/A')[:30],
                f"{scan.get('risk_score', 0):.1f}",
                str(scan.get('vulnerability_count', 0))
            ])
        
        history_table = Table(table_data, colWidths=[1.5*inch, 3*inch, 1*inch, 1*inch])
        history_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))
        
        story.append(history_table)
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['BodyText']
        ))
        
        doc.build(story)
        
        return output_path


def generate_vulnerability_report(scan_data: Dict, vulnerabilities: List[Dict], 
                                  ai_analysis: Dict, output_dir: str = "reports") -> str:
    """Generate vulnerability report PDF"""
    
    # Create output directory if needed
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate filename
    url_hash = hash(scan_data.get('url', 'unknown'))
    filename = f"vulnerability_report_{url_hash}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(output_dir, filename)
    
    generator = PDFReportGenerator()
    return generator.generate_report(scan_data, vulnerabilities, ai_analysis, output_path)


def generate_history_report(scan_history: List[Dict], output_dir: str = "reports") -> str:
    """Generate scan history report PDF"""
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    filename = f"scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(output_dir, filename)
    
    generator = PDFReportGenerator()
    return generator.generate_summary_report(scan_history, output_path)
