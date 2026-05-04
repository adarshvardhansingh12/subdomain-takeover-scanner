from datetime import datetime

SEVERITY_COLOR = {
    "critical": "#c0392b",
    "high":     "#e74c3c",
    "medium":   "#e67e22",
    "low":      "#2980b9",
    "info":     "#7f8c8d",
}


class HTMLReporter:
    def __init__(self, domain: str, subdomains: list[dict], findings: list[dict], output_path: str):
        self.domain = domain
        self.subdomains = subdomains
        self.findings = findings
        self.output_path = output_path

    def _badge(self, sev: str) -> str:
        color = SEVERITY_COLOR.get(sev, "#999")
        return (f'<span style="background:{color};color:#fff;padding:3px 10px;'
                f'border-radius:20px;font-size:11px;font-weight:700;'
                f'letter-spacing:0.5px;">{sev.upper()}</span>')

    def _conf_badge(self, conf: str) -> str:
        colors = {"confirmed": "#27ae60", "high": "#2ecc71", "medium": "#e67e22", "low": "#e74c3c"}
        color = colors.get(conf, "#999")
        return (f'<span style="background:{color}22;color:{color};border:1px solid {color};'
                f'padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;">'
                f'{conf.upper()}</span>')

    def _summary_cards(self) -> str:
        counts = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        def card(label, value, color, icon):
            return f"""
            <div class="stat-card" style="border-top:4px solid {color};">
              <div class="stat-icon">{icon}</div>
              <div class="stat-value" style="color:{color};">{value}</div>
              <div class="stat-label">{label}</div>
            </div>"""

        cards = card("Subdomains Found", len(self.subdomains), "#2ecc71", "🌐")
        cards += card("Vulnerable", len(self.findings), "#e74c3c", "⚠️")
        cards += card("Critical", counts.get("critical", 0), "#c0392b", "🔴")
        cards += card("High", counts.get("high", 0), "#e74c3c", "🟠")
        cards += card("Medium", counts.get("medium", 0), "#e67e22", "🟡")
        cards += card("Low", counts.get("low", 0), "#2980b9", "🔵")
        return f'<div class="stats-grid">{cards}</div>'

    def _finding_cards(self) -> str:
        if not self.findings:
            return '<div class="empty-state">✅ No vulnerable subdomains detected. Domain appears clean.</div>'

        cards = ""
        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "info")
            color = SEVERITY_COLOR.get(sev, "#999")
            conf = f.get("confidence", "low")
            cname = f.get("cname") or "N/A"
            a_records = ", ".join(f.get("a_records", [])) or "N/A"
            status = f.get("status_code", "")

            cards += f"""
            <div class="finding-card" style="border-left:5px solid {color};">
              <div class="finding-header">
                <div class="finding-title">
                  <span class="finding-num">#{i}</span>
                  <span class="finding-domain">{f.get('subdomain','')}</span>
                </div>
                <div class="finding-badges">
                  {self._badge(sev)}
                  {self._conf_badge(conf)}
                </div>
              </div>
              <div class="finding-body">
                <div class="finding-grid">
                  <div class="finding-field">
                    <span class="field-label">Service</span>
                    <span class="field-value">{f.get('service','')}</span>
                  </div>
                  <div class="finding-field">
                    <span class="field-label">HTTP Status</span>
                    <span class="field-value">{status}</span>
                  </div>
                  <div class="finding-field">
                    <span class="field-label">CNAME Target</span>
                    <span class="field-value mono">{cname}</span>
                  </div>
                  <div class="finding-field">
                    <span class="field-label">A Records</span>
                    <span class="field-value mono">{a_records}</span>
                  </div>
                </div>
                <div class="finding-field full-width">
                  <span class="field-label">Description</span>
                  <span class="field-value">{f.get('description','')}</span>
                </div>
                <div class="finding-field full-width remediation">
                  <span class="field-label">🔧 Remediation</span>
                  <span class="field-value">{f.get('remediation','')}</span>
                </div>
                <div class="finding-field full-width">
                  <span class="field-label">References</span>
                  <span class="field-value">
                    <a href="{f.get('references','#')}" target="_blank">{f.get('references','')}</a>
                  </span>
                </div>
              </div>
            </div>"""
        return cards

    def _subdomain_rows(self) -> str:
        vuln_subs = {f["subdomain"] for f in self.findings}
        rows = ""
        for s in sorted(self.subdomains, key=lambda x: x["subdomain"]):
            sub = s["subdomain"]
            is_vuln = sub in vuln_subs
            is_dangling = s.get("is_dangling", False)
            cname = s.get("cname") or "—"
            a_recs = ", ".join(s.get("a_records", [])) or "—"
            source = s.get("source", "")

            if is_vuln:
                status_badge = '<span class="badge badge-vuln">VULNERABLE</span>'
            elif is_dangling:
                status_badge = '<span class="badge badge-dangling">DANGLING</span>'
            else:
                status_badge = '<span class="badge badge-clean">CLEAN</span>'

            rows += f"""
            <tr>
              <td class="mono td-sub">{sub}</td>
              <td class="mono td-cname">{cname}</td>
              <td class="mono td-a">{a_recs}</td>
              <td class="td-src"><span class="source-tag">{source}</span></td>
              <td class="td-status">{status_badge}</td>
            </tr>"""
        return rows

    def generate(self):
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Subdomain Takeover Report – {self.domain}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg: #0f1117;
    --surface: #1a1d2e;
    --surface2: #22263a;
    --border: #2e3150;
    --text: #e2e8f0;
    --text-muted: #8892a4;
    --accent: #e74c3c;
  }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.6;
  }}

  /* Header */
  header {{
    background: linear-gradient(135deg, #1a1d2e 0%, #0f1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 28px 40px;
    display: flex;
    align-items: center;
    gap: 20px;
  }}
  .header-icon {{ font-size: 40px; }}
  .header-title h1 {{ font-size: 22px; font-weight: 700; color: #fff; }}
  .header-title p {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
  .header-meta {{
    margin-left: auto;
    text-align: right;
    font-size: 12px;
    color: var(--text-muted);
    line-height: 1.8;
  }}

  /* Layout */
  main {{ max-width: 1200px; margin: 32px auto; padding: 0 24px; }}

  /* Section */
  .section {{ margin-bottom: 32px; }}
  .section-title {{
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  /* Stats */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
  }}
  .stat-card {{
    background: var(--surface);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    border: 1px solid var(--border);
    transition: transform 0.2s;
  }}
  .stat-card:hover {{ transform: translateY(-2px); }}
  .stat-icon {{ font-size: 24px; margin-bottom: 8px; }}
  .stat-value {{ font-size: 32px; font-weight: 800; line-height: 1; margin-bottom: 6px; }}
  .stat-label {{ font-size: 12px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}

  /* Finding cards */
  .finding-card {{
    background: var(--surface);
    border-radius: 12px;
    margin-bottom: 16px;
    border: 1px solid var(--border);
    overflow: hidden;
  }}
  .finding-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    background: var(--surface2);
    flex-wrap: wrap;
    gap: 10px;
  }}
  .finding-title {{ display: flex; align-items: center; gap: 12px; }}
  .finding-num {{
    background: var(--border);
    color: var(--text-muted);
    width: 28px; height: 28px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700;
    flex-shrink: 0;
  }}
  .finding-domain {{ font-size: 15px; font-weight: 700; font-family: monospace; word-break: break-all; }}
  .finding-badges {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .finding-body {{ padding: 20px; }}
  .finding-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
    margin-bottom: 14px;
  }}
  .finding-field {{ display: flex; flex-direction: column; gap: 4px; }}
  .finding-field.full-width {{ margin-top: 12px; }}
  .field-label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }}
  .field-value {{ font-size: 13px; color: var(--text); word-break: break-word; }}
  .field-value a {{ color: #5b8dee; text-decoration: none; }}
  .field-value a:hover {{ text-decoration: underline; }}
  .remediation {{ background: #1a2a1a; border-radius: 8px; padding: 12px; border: 1px solid #2d4a2d; }}
  .remediation .field-label {{ color: #5cb85c; }}

  /* Subdomains table */
  .table-wrap {{ background: var(--surface); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; }}
  .table-search {{
    padding: 16px 20px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
  }}
  .table-search input {{
    width: 100%;
    max-width: 360px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 14px;
    color: var(--text);
    font-size: 13px;
    outline: none;
  }}
  .table-search input:focus {{ border-color: #5b8dee; }}
  .table-scroll {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; min-width: 700px; }}
  thead th {{
    background: var(--surface2);
    padding: 12px 16px;
    text-align: left;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    white-space: nowrap;
    border-bottom: 1px solid var(--border);
  }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background 0.15s; }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: var(--surface2); }}
  td {{ padding: 11px 16px; vertical-align: middle; }}
  .td-sub {{ font-weight: 600; font-size: 13px; word-break: break-all; }}
  .td-cname, .td-a {{ font-size: 12px; color: var(--text-muted); word-break: break-all; }}
  .mono {{ font-family: 'Courier New', monospace; }}

  /* Badges */
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
    white-space: nowrap;
  }}
  .badge-vuln {{ background: #c0392b22; color: #e74c3c; border: 1px solid #e74c3c; }}
  .badge-dangling {{ background: #e67e2222; color: #e67e22; border: 1px solid #e67e22; }}
  .badge-clean {{ background: #27ae6022; color: #2ecc71; border: 1px solid #27ae60; }}
  .source-tag {{
    background: var(--border);
    color: var(--text-muted);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-family: monospace;
  }}

  /* Empty state */
  .empty-state {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 40px;
    text-align: center;
    color: #2ecc71;
    font-size: 16px;
  }}

  /* Footer */
  footer {{
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
    padding: 32px 24px;
    border-top: 1px solid var(--border);
    margin-top: 32px;
  }}
</style>
</head>
<body>

<header>
  <div class="header-icon">🔍</div>
  <div class="header-title">
    <h1>Subdomain Takeover Report</h1>
    <p>Target: <strong>{self.domain}</strong></p>
  </div>
  <div class="header-meta">
    <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    <div>Subdomains scanned: <strong>{len(self.subdomains)}</strong></div>
    <div>Vulnerable found: <strong style="color:#e74c3c;">{len(self.findings)}</strong></div>
  </div>
</header>

<main>

  <!-- Summary -->
  <div class="section">
    <div class="section-title">📊 Executive Summary</div>
    {self._summary_cards()}
  </div>

  <!-- Vulnerable Findings -->
  <div class="section">
    <div class="section-title">⚠️ Vulnerable Subdomains ({len(self.findings)})</div>
    {self._finding_cards()}
  </div>

  <!-- All Subdomains Table -->
  <div class="section">
    <div class="section-title">🌐 All Discovered Subdomains ({len(self.subdomains)})</div>
    <div class="table-wrap">
      <div class="table-search">
        <input type="text" id="searchInput" placeholder="🔎  Filter subdomains..." onkeyup="filterTable()">
      </div>
      <div class="table-scroll">
        <table id="subTable">
          <thead>
            <tr>
              <th>Subdomain</th>
              <th>CNAME Target</th>
              <th>A Records</th>
              <th>Source</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {self._subdomain_rows()}
          </tbody>
        </table>
      </div>
    </div>
  </div>

</main>

<footer>
  ReconStrike — Subdomain Takeover Scanner &nbsp;|&nbsp; For authorized security testing only &nbsp;|&nbsp; {datetime.now().strftime('%Y')}
</footer>

<script>
  function filterTable() {{
    const input = document.getElementById('searchInput').value.toLowerCase();
    const rows = document.querySelectorAll('#subTable tbody tr');
    rows.forEach(row => {{
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(input) ? '' : 'none';
    }});
  }}
</script>

</body>
</html>"""

        with open(self.output_path, "w") as f:
            f.write(html)
