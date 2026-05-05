
class HTMLReporter:
    def __init__(self, domain, findings, output_path):
        self.domain = domain
        self.findings = findings
        self.output_path = output_path

    def generate(self):
        html = self._build_html()

        # ✅ FIXED: proper indentation + UTF-8 encoding
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_html(self):
        total = len(self.findings)
        vulnerable = [f for f in self.findings if f.get("vulnerable")]

        html = f"""
        <html>
        <head>
            <title>Subdomain Takeover Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background: #0f172a;
                    color: #e2e8f0;
                    padding: 20px;
                }}
                h1 {{
                    color: #22c55e;
                }}
                .card {{
                    background: #1e293b;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 8px;
                }}
                .safe {{
                    color: #22c55e;
                }}
                .vuln {{
                    color: #ef4444;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 10px;
                    border-bottom: 1px solid #334155;
                }}
            </style>
        </head>
        <body>

        <h1>Subdomain Takeover Report</h1>

        <div class="card">
            <strong>Domain:</strong> {self.domain}<br>
            <strong>Total Subdomains:</strong> {total}<br>
            <strong>Vulnerable:</strong> {len(vulnerable)}
        </div>

        <table>
            <tr>
                <th>Subdomain</th>
                <th>Status</th>
                <th>CNAME</th>
            </tr>
        """

        for f in self.findings:
            status = "VULNERABLE" if f.get("vulnerable") else "SAFE"
            cls = "vuln" if f.get("vulnerable") else "safe"

            html += f"""
            <tr>
                <td>{f.get('subdomain')}</td>
                <td class="{cls}">{status}</td>
                <td>{f.get('cname') or '-'}</td>
            </tr>
            """

        html += """
        </table>
        </body>
        </html>
        """

        return html
