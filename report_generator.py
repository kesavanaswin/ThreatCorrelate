"""
Report Generator - Creates professional PDF threat intelligence reports
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import io

class ReportGenerator:
    """
    Generates professional PDF threat intelligence reports
    """
    
    def __init__(self):
        """Initialize report generator"""
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()
    
    def _add_custom_styles(self):
        """Add custom paragraph styles"""
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#FF0000'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Normal style
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=12,
            spaceAfter=6
        ))
        
        # Verdict styles
        self.styles.add(ParagraphStyle(
            name='VerdictMalicious',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='VerdictSuspicious',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.orange,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='VerdictClean',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.green,
            fontName='Helvetica-Bold'
        ))
    
    def get_verdict_color(self, verdict):
        """Get color for verdict"""
        colors_map = {
            'Malicious': colors.red,
            'Suspicious': colors.orange,
            'Low Risk': colors.yellow,
            'Clean': colors.green
        }
        return colors_map.get(verdict, colors.black)
    
    def generate_summary_table(self, results):
        """Generate summary statistics table"""
        
        total = len(results)
        malicious = sum(1 for r in results if r['verdict'] == 'Malicious')
        suspicious = sum(1 for r in results if r['verdict'] == 'Suspicious')
        low_risk = sum(1 for r in results if r['verdict'] == 'Low Risk')
        clean = sum(1 for r in results if r['verdict'] == 'Clean')
        
        summary_data = [
            ['Metric', 'Count', 'Percentage'],
            ['Total IOCs', str(total), '100%'],
            ['Malicious', str(malicious), f'{(malicious/total*100):.1f}%'],
            ['Suspicious', str(suspicious), f'{(suspicious/total*100):.1f}%'],
            ['Low Risk', str(low_risk), f'{(low_risk/total*100):.1f}%'],
            ['Clean', str(clean), f'{(clean/total*100):.1f}%']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        
        return summary_table
    
    def generate_detailed_findings_table(self, results):
        """Generate detailed findings table"""
        
        findings_data = [
            ['IOC', 'Type', 'Score', 'Verdict', 'VT', 'AbuseIPDB', 'OTX', 'MITRE Technique']
        ]
        
        for result in results:
            findings_data.append([
                result['ioc'][:30],  # Truncate long IOCs
                result['type'],
                str(result['score']),
                result['verdict'],
                str(result['vt_detections']),
                str(result['abuseipdb_score']),
                str(result['otx_pulses']),
                result['primary_technique']
            ])
        
        findings_table = Table(findings_data, colWidths=[1.2*inch, 0.8*inch, 0.6*inch, 0.8*inch, 0.6*inch, 0.8*inch, 0.6*inch, 1*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        
        return findings_table
    
    def generate_ioc_detail_sections(self, results):
        """Generate detailed sections for each IOC"""
        
        sections = []
        
        for idx, result in enumerate(results):
            # IOC heading
            ioc_heading = Paragraph(
                f"<b>{idx + 1}. {result['ioc']}</b>",
                self.styles['CustomHeading']
            )
            sections.append(ioc_heading)
            
            # IOC details
            ioc_details = [
                ['Field', 'Value'],
                ['IOC Type', result['type']],
                ['Confidence Score', f"{result['score']}/100"],
                ['Verdict', result['verdict']],
                ['VT Detections', str(result['vt_detections'])],
                ['AbuseIPDB Score', str(result['abuseipdb_score'])],
                ['OTX Pulses', str(result['otx_pulses'])],
                ['Primary Technique', result['primary_technique']],
                ['Technique Name', result['technique_name']],
            ]
            
            ioc_table = Table(ioc_details, colWidths=[2*inch, 4*inch])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
            ]))
            
            sections.append(ioc_table)
            sections.append(Spacer(1, 0.3*inch))
            
            # Tags section
            if result['tags']:
                tags_para = Paragraph(
                    f"<b>Tags:</b> {', '.join(result['tags'][:10])}",
                    self.styles['CustomNormal']
                )
                sections.append(tags_para)
                sections.append(Spacer(1, 0.1*inch))
            
            # MITRE Tactics
            tactics_str = ', '.join(result['tactics'].keys()) if result['tactics'] else 'N/A'
            tactics_para = Paragraph(
                f"<b>MITRE ATT&CK Tactics:</b> {tactics_str}",
                self.styles['CustomNormal']
            )
            sections.append(tactics_para)
            sections.append(Spacer(1, 0.3*inch))
        
        return sections
    
    def generate_pdf(self, results, filename=None):
        """
        Generate complete PDF report
        
        Args:
            results: List of analysis results
            filename: Output filename (default: threat_report_[timestamp].pdf)
        
        Returns:
            BytesIO object containing PDF data or filename if saved to disk
        """
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"threat_report_{timestamp}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
            title="ThreatCorrelate Report"
        )
        
        # Build document content
        content = []
        
        # Title page
        title = Paragraph(
            "<b>🛡️ ThreatCorrelate</b><br/><b>Threat Intelligence Correlation Report</b>",
            self.styles['CustomTitle']
        )
        content.append(title)
        content.append(Spacer(1, 0.3*inch))
        
        # Report metadata
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        metadata = Paragraph(
            f"<b>Report Generated:</b> {timestamp}<br/><b>Total IOCs Analyzed:</b> {len(results)}",
            self.styles['CustomNormal']
        )
        content.append(metadata)
        content.append(Spacer(1, 0.5*inch))
        
        # Executive Summary
        summary_heading = Paragraph("Executive Summary", self.styles['CustomHeading'])
        content.append(summary_heading)
        
        summary_text = Paragraph(
            "This report presents the results of automated threat intelligence correlation analysis. "
            "Multiple threat intelligence sources (VirusTotal, AbuseIPDB, AlienVault OTX) were queried "
            "and results were correlated using a weighted confidence scoring formula. MITRE ATT&CK "
            "techniques are mapped to identified threats for tactical context.",
            self.styles['CustomNormal']
        )
        content.append(summary_text)
        content.append(Spacer(1, 0.3*inch))
        
        # Summary Statistics
        stats_heading = Paragraph("Summary Statistics", self.styles['CustomHeading'])
        content.append(stats_heading)
        
        summary_table = self.generate_summary_table(results)
        content.append(summary_table)
        content.append(Spacer(1, 0.5*inch))
        
        # Detailed Findings Table
        findings_heading = Paragraph("Detailed Findings", self.styles['CustomHeading'])
        content.append(findings_heading)
        
        findings_table = self.generate_detailed_findings_table(results)
        content.append(findings_table)
        content.append(Spacer(1, 0.5*inch))
        
        # Page break before detailed analysis
        content.append(PageBreak())
        
        # Detailed Analysis
        analysis_heading = Paragraph("Detailed IOC Analysis", self.styles['CustomHeading'])
        content.append(analysis_heading)
        content.append(Spacer(1, 0.2*inch))
        
        ioc_sections = self.generate_ioc_detail_sections(results)
        content.extend(ioc_sections)
        
        # Recommendations
        content.append(PageBreak())
        
        recommendations_heading = Paragraph("Recommendations & Guidance", self.styles['CustomHeading'])
        content.append(recommendations_heading)
        
        recommendations = Paragraph(
            """
            <b>For Malicious IOCs:</b> Implement immediate blocking at firewall and DNS levels. 
            Quarantine affected systems and perform threat hunting for indicators of compromise.<br/><br/>
            
            <b>For Suspicious IOCs:</b> Increase monitoring and logging. Conduct threat hunting. 
            Correlate with other security alerts and logs.<br/><br/>
            
            <b>For Low Risk IOCs:</b> Continue normal monitoring. Periodically re-check reputation.<br/><br/>
            
            <b>MITRE ATT&CK Mapping:</b> Use the mapped techniques to understand attacker tactics and 
            implement defensive controls specific to those techniques.
            """,
            self.styles['CustomNormal']
        )
        content.append(recommendations)
        content.append(Spacer(1, 0.5*inch))
        
        # Methodology
        methodology_heading = Paragraph("Methodology", self.styles['CustomHeading'])
        content.append(methodology_heading)
        
        methodology = Paragraph(
            """
            <b>Scoring Formula:</b> Final Score = (VT × 0.5) + (AbuseIPDB × 0.3) + (OTX × 0.2)<br/>
            
            <b>Thresholds:</b><br/>
            • Malicious: 80-100 (High confidence threat)<br/>
            • Suspicious: 50-79 (Requires investigation)<br/>
            • Low Risk: 20-49 (Minor concerns)<br/>
            • Clean: 0-19 (Appears safe)<br/><br/>
            
            <b>Data Sources:</b><br/>
            • VirusTotal: Aggregated antivirus detections (50% weight)<br/>
            • AbuseIPDB: IP reputation and abuse reports (30% weight)<br/>
            • AlienVault OTX: Threat pulse correlation (20% weight)
            """,
            self.styles['CustomNormal']
        )
        content.append(methodology)
        
        # Build PDF
        doc.build(content)
        
        return filename
    
    @staticmethod
    def generate_pdf_bytes(results):
        """
        Generate PDF and return as bytes
        
        Args:
            results: List of analysis results
        
        Returns:
            BytesIO object containing PDF data
        """
        generator = ReportGenerator()
        
        # Create PDF in memory
        pdf_buffer = io.BytesIO()
        
        # Create document
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        # Build content
        content = []
        
        # Title
        title = Paragraph(
            "<b>🛡️ ThreatCorrelate</b><br/><b>Threat Intelligence Correlation Report</b>",
            generator.styles['CustomTitle']
        )
        content.append(title)
        content.append(Spacer(1, 0.3*inch))
        
        # Metadata
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        metadata = Paragraph(
            f"<b>Report Generated:</b> {timestamp}<br/><b>Total IOCs Analyzed:</b> {len(results)}",
            generator.styles['CustomNormal']
        )
        content.append(metadata)
        content.append(Spacer(1, 0.5*inch))
        
        # Summary
        summary_heading = Paragraph("Summary Statistics", generator.styles['CustomHeading'])
        content.append(summary_heading)
        
        summary_table = generator.generate_summary_table(results)
        content.append(summary_table)
        content.append(Spacer(1, 0.3*inch))
        
        # Findings table
        findings_heading = Paragraph("Detailed Findings", generator.styles['CustomHeading'])
        content.append(findings_heading)
        
        findings_table = generator.generate_detailed_findings_table(results)
        content.append(findings_table)
        
        # Build PDF
        doc.build(content)
        
        # Return buffer
        pdf_buffer.seek(0)
        return pdf_buffer


# Test the report generator
if __name__ == "__main__":
    print("Testing Report Generator...\n")
    
    # Sample results
    sample_results = [
        {
            'ioc': '8.8.8.8',
            'type': 'ipv4',
            'score': 0.0,
            'verdict': 'Clean',
            'vt_detections': 0,
            'abuseipdb_score': 0,
            'otx_pulses': 0,
            'tags': [],
            'primary_technique': 'Unknown',
            'technique_name': 'Unknown',
            'techniques': [],
            'tactics': {}
        },
        {
            'ioc': 'malicious.com',
            'type': 'domain',
            'score': 70.0,
            'verdict': 'Suspicious',
            'vt_detections': 11,
            'abuseipdb_score': 0,
            'otx_pulses': 4,
            'tags': ['stealer', 'trojan', 'c2'],
            'primary_technique': 'T1041',
            'technique_name': 'Exfiltration Over C2 Channel',
            'techniques': ['T1041', 'T1071'],
            'tactics': {'Exfiltration': ['T1041'], 'Command and Control': ['T1071']}
        }
    ]
    
    # Generate report
    generator = ReportGenerator()
    filename = generator.generate_pdf(sample_results)
    print(f"✓ PDF Report generated: {filename}")
    print("Report generator ready to use!")
