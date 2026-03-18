"""
Reports Router
==============
Enhanced PDF reporting with multiple report types and robust error handling.
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from datetime import datetime, timezone, timedelta
from typing import Optional
import io
import traceback

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

from .dependencies import (
    get_current_user, get_db, check_permission, logger
)
from .ai_analysis import call_openai

router = APIRouter(prefix="/reports", tags=["Reports"])


def safe_str(value, max_length=50, default="N/A"):
    """Safely convert value to string with length limit"""
    try:
        if value is None:
            return default
        result = str(value)
        if len(result) > max_length:
            return result[:max_length-3] + "..."
        return result
    except Exception:
        return default


def create_pie_chart(data: dict, width=200, height=150):
    """Create a pie chart drawing"""
    try:
        drawing = Drawing(width, height)
        pie = Pie()
        pie.x = 50
        pie.y = 25
        pie.width = 100
        pie.height = 100
        
        values = list(data.values())
        labels = list(data.keys())
        
        if sum(values) == 0:
            return None
        
        pie.data = values
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        
        # Color scheme
        chart_colors = [
            colors.HexColor('#EF4444'),  # Red
            colors.HexColor('#F97316'),  # Orange
            colors.HexColor('#FBBF24'),  # Yellow
            colors.HexColor('#22C55E'),  # Green
            colors.HexColor('#3B82F6'),  # Blue
        ]
        
        for i, _ in enumerate(values):
            if i < len(chart_colors):
                pie.slices[i].fillColor = chart_colors[i]
        
        drawing.add(pie)
        return drawing
    except Exception as e:
        logger.warning(f"Chart creation failed: {e}")
        return None


def generate_threat_report_pdf(threats: list, alerts: list, stats: dict, 
                                include_charts: bool = True) -> io.BytesIO:
    """Generate PDF threat intelligence report with enhanced formatting"""
    buffer = io.BytesIO()
    
    try:
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=A4, 
            rightMargin=50, 
            leftMargin=50, 
            topMargin=50, 
            bottomMargin=50
        )
        
        styles = getSampleStyleSheet()
        
        # Define custom styles
        styles.add(ParagraphStyle(
            name='TitleStyle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#3B82F6'),
            alignment=1  # Center
        ))
        styles.add(ParagraphStyle(
            name='SubtitleStyle',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=20,
            textColor=colors.HexColor('#64748B'),
            alignment=1  # Center
        ))
        styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#1E293B')
        ))
        styles.add(ParagraphStyle(
            name='CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=8
        ))
        styles.add(ParagraphStyle(
            name='FooterStyle',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#94A3B8'),
            alignment=1
        ))
        
        elements = []
        
        # Title Page
        elements.append(Spacer(1, 100))
        elements.append(Paragraph("SERAPH AI", styles['TitleStyle']))
        elements.append(Paragraph("THREAT INTELLIGENCE REPORT", styles['TitleStyle']))
        elements.append(Spacer(1, 30))
        elements.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", 
            styles['SubtitleStyle']
        ))
        elements.append(Paragraph("Classification: CONFIDENTIAL", styles['SubtitleStyle']))
        elements.append(PageBreak())
        
        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", styles['SectionTitle']))
        
        summary_data = [
            ['Metric', 'Value', 'Status'],
            ['Total Threats', str(stats.get('total_threats', 0)), 
             'Critical' if stats.get('total_threats', 0) > 50 else 'Normal'],
            ['Active Threats', str(stats.get('active_threats', 0)),
             'Critical' if stats.get('active_threats', 0) > 10 else 'Normal'],
            ['Contained Threats', str(stats.get('contained_threats', 0)), 'Resolved'],
            ['Resolved Threats', str(stats.get('resolved_threats', 0)), 'Resolved'],
            ['Critical Alerts', str(stats.get('critical_alerts', 0)),
             'Critical' if stats.get('critical_alerts', 0) > 0 else 'Normal'],
            ['System Health', f"{stats.get('system_health', 100):.1f}%",
             'Good' if stats.get('system_health', 100) >= 80 else 'Degraded']
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 100, 80])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3B82F6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1E293B')),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('ROWHEIGHT', (0, 0), (-1, -1), 28),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 30))
        
        # Severity Distribution Chart
        if include_charts:
            severity_data = {
                'Critical': len([t for t in threats if t.get('severity') == 'critical']),
                'High': len([t for t in threats if t.get('severity') == 'high']),
                'Medium': len([t for t in threats if t.get('severity') == 'medium']),
                'Low': len([t for t in threats if t.get('severity') == 'low']),
            }
            
            if sum(severity_data.values()) > 0:
                elements.append(Paragraph("THREAT SEVERITY DISTRIBUTION", styles['SectionTitle']))
                chart = create_pie_chart(severity_data)
                if chart:
                    elements.append(chart)
                elements.append(Spacer(1, 20))
        
        # Active Threats Section
        elements.append(Paragraph("ACTIVE THREATS", styles['SectionTitle']))
        active_threats = [t for t in threats if t.get('status') == 'active']
        
        if active_threats:
            threat_data = [['Name', 'Type', 'Severity', 'Source']]
            for threat in active_threats[:15]:
                threat_data.append([
                    safe_str(threat.get('name', 'Unknown'), 35),
                    safe_str(threat.get('type', 'Unknown'), 20),
                    safe_str(threat.get('severity', 'Unknown'), 10).upper(),
                    safe_str(threat.get('source_ip', 'N/A'), 15)
                ])
            
            threat_table = Table(threat_data, colWidths=[150, 100, 70, 100])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EF4444')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
                ('ROWHEIGHT', (0, 0), (-1, -1), 24),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                # Alternate row colors
                *[('BACKGROUND', (0, i), (-1, i), colors.HexColor('#FEF2F2' if i % 2 == 0 else '#FFFFFF')) 
                  for i in range(1, len(threat_data))]
            ]))
            elements.append(threat_table)
        else:
            elements.append(Paragraph("No active threats at this time.", styles['CustomBody']))
        
        elements.append(Spacer(1, 30))
        
        # Recent Alerts Section
        elements.append(Paragraph("RECENT ALERTS", styles['SectionTitle']))
        if alerts:
            alert_data = [['Title', 'Type', 'Severity', 'Status']]
            for alert in alerts[:15]:
                alert_data.append([
                    safe_str(alert.get('title', 'Unknown'), 40),
                    safe_str(alert.get('type', 'Unknown'), 20),
                    safe_str(alert.get('severity', 'Unknown'), 10).upper(),
                    safe_str(alert.get('status', 'Unknown'), 15)
                ])
            
            alert_table = Table(alert_data, colWidths=[170, 100, 70, 80])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F59E0B')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
                ('ROWHEIGHT', (0, 0), (-1, -1), 24),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(alert_table)
        else:
            elements.append(Paragraph("No recent alerts.", styles['CustomBody']))
        
        elements.append(Spacer(1, 50))
        
        # Footer
        elements.append(Paragraph("--- End of Report ---", styles['FooterStyle']))
        elements.append(Paragraph("Generated by Seraph AI Defense System", styles['FooterStyle']))
        elements.append(Paragraph("This report is confidential and intended for authorized personnel only.", styles['FooterStyle']))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        logger.error(f"PDF generation error: {e}\n{traceback.format_exc()}")
        # Return a simple error PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = [
            Paragraph("Error Generating Report", styles['Heading1']),
            Paragraph(f"An error occurred: {safe_str(str(e), 200)}", styles['Normal']),
            Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}", styles['Normal']),
        ]
        doc.build(elements)
        buffer.seek(0)
        return buffer

@router.get("/threat-intelligence")
async def generate_threat_report(current_user: dict = Depends(check_permission("export_reports"))):
    """Generate PDF threat intelligence report"""
    db = get_db()
    
    # Gather data
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    
    # Calculate stats
    total_threats = len(threats)
    active_threats = len([t for t in threats if t.get('status') == 'active'])
    contained_threats = len([t for t in threats if t.get('status') == 'contained'])
    resolved_threats = len([t for t in threats if t.get('status') == 'resolved'])
    critical_alerts = len([a for a in alerts if a.get('severity') == 'critical' and a.get('status') != 'resolved'])
    
    system_health = 100.0
    if total_threats > 0:
        system_health = ((contained_threats + resolved_threats) / total_threats) * 100
    
    stats = {
        'total_threats': total_threats,
        'active_threats': active_threats,
        'contained_threats': contained_threats,
        'resolved_threats': resolved_threats,
        'critical_alerts': critical_alerts,
        'system_health': system_health
    }
    
    # Generate PDF
    pdf_buffer = generate_threat_report_pdf(threats, alerts, stats)
    
    filename = f"threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/ai-summary")
async def generate_ai_summary_report(current_user: dict = Depends(check_permission("export_reports"))):
    """Generate AI-powered threat summary"""
    db = get_db()
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    
    context = f"""
Threats Summary:
- Total: {len(threats)}
- Active: {len([t for t in threats if t.get('status') == 'active'])}
- Types: {', '.join(set(t.get('type', 'unknown') for t in threats))}

Alerts Summary:
- Total: {len(alerts)}
- Critical: {len([a for a in alerts if a.get('severity') == 'critical'])}

Recent Threat Names:
{chr(10).join(['- ' + t.get('name', 'Unknown') for t in threats[:5]])}
"""
    
    system_message = """You are a cybersecurity analyst. Provide a concise executive summary of the current threat landscape based on the data provided. Include:
1. Overall risk assessment (Critical/High/Medium/Low)
2. Key findings (3-5 bullet points)
3. Recommended immediate actions (2-3 points)
4. Trend analysis

Keep the summary professional and actionable."""

    try:
        summary = await call_openai(system_message, f"Analyze this security data and provide an executive summary:\n{context}")
        return {
            "summary": summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_points": {
                "threats_analyzed": len(threats),
                "alerts_analyzed": len(alerts)
            }
        }
    except Exception as e:
        logger.error(f"AI summary generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate summary: {str(e)}")



@router.get("/stress-test")
async def stress_test_reports(
    iterations: int = Query(default=10, le=100, ge=1),
    current_user: dict = Depends(get_current_user)
):
    """
    Stress test PDF report generation.
    Generates multiple reports to verify stability.
    """
    results = {
        "total_iterations": iterations,
        "successful": 0,
        "failed": 0,
        "errors": [],
        "timing_ms": []
    }
    
    # Generate test data
    test_threats = [
        {
            "id": f"threat_{i}",
            "name": f"Test Threat {i}",
            "severity": ["critical", "high", "medium", "low"][i % 4],
            "type": ["malware", "phishing", "ransomware", "credential_theft"][i % 4],
            "status": "active",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "description": f"This is test threat number {i} for stress testing the PDF generation system."
        }
        for i in range(50)
    ]
    
    test_alerts = [
        {
            "id": f"alert_{i}",
            "message": f"Test alert message {i}",
            "severity": ["critical", "high", "medium", "low"][i % 4],
            "acknowledged": i % 2 == 0,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        for i in range(100)
    ]
    
    test_stats = {
        "critical_threats": 10,
        "high_threats": 15,
        "medium_threats": 20,
        "low_threats": 5,
        "total_alerts": 100,
        "acknowledged_alerts": 50,
        "active_agents": 5
    }
    
    import time
    
    for i in range(iterations):
        start_time = time.time()
        try:
            pdf_buffer = generate_threat_report_pdf(
                test_threats,
                test_alerts,
                test_stats,
                include_charts=True
            )
            
            # Verify PDF is valid
            pdf_data = pdf_buffer.getvalue()
            if pdf_data[:4] != b'%PDF':
                raise ValueError("Invalid PDF header")
            
            results["successful"] += 1
            
        except Exception as e:
            results["failed"] += 1
            results["errors"].append({
                "iteration": i + 1,
                "error": str(e),
                "traceback": traceback.format_exc()[:500]
            })
        
        elapsed_ms = (time.time() - start_time) * 1000
        results["timing_ms"].append(round(elapsed_ms, 2))
    
    # Calculate statistics
    if results["timing_ms"]:
        results["avg_time_ms"] = round(sum(results["timing_ms"]) / len(results["timing_ms"]), 2)
        results["min_time_ms"] = min(results["timing_ms"])
        results["max_time_ms"] = max(results["timing_ms"])
    
    results["success_rate"] = f"{(results['successful'] / iterations) * 100:.1f}%"
    
    # Only keep first 5 errors to avoid huge response
    results["errors"] = results["errors"][:5]
    # Remove individual timings if too many
    if len(results["timing_ms"]) > 20:
        results["timing_ms"] = results["timing_ms"][:20] + ["..."]
    
    return results


@router.get("/health")
async def report_health():
    """Check PDF generation health"""
    try:
        # Generate a minimal PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [Paragraph("Health Check", styles['Heading1'])]
        doc.build(story)
        
        pdf_data = buffer.getvalue()
        
        return {
            "status": "healthy",
            "pdf_generation": "working",
            "pdf_size_bytes": len(pdf_data),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
