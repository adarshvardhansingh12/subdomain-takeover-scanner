from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}

CONFIDENCE_COLORS = {
    "confirmed": "bold green",
    "high":      "green",
    "medium":    "yellow",
    "low":       "red",
}


class TerminalReporter:
    def __init__(self, domain: str, subdomains: list[dict], findings: list[dict]):
        self.domain = domain
        self.subdomains = subdomains
        self.findings = findings

    def _severity_text(self, sev: str) -> str:
        color = SEVERITY_COLORS.get(sev, "white")
        return f"[{color}]{sev.upper()}[/{color}]"

    def _confidence_text(self, conf: str) -> str:
        color = CONFIDENCE_COLORS.get(conf, "white")
        return f"[{color}]{conf.upper()}[/{color}]"

    def print(self):
        # ── Summary Panel ──────────────────────────────────────────────────
        counts = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        vuln_color = "red" if self.findings else "green"
        summary_lines = (
            f"[bold]Domain:[/bold]            {self.domain}\n"
            f"[bold]Subdomains found:[/bold]  {len(self.subdomains)}\n"
            f"[bold]Vulnerable:[/bold]        [{vuln_color}]{len(self.findings)}[/{vuln_color}]\n"
            f"[bold]Critical:[/bold]          [bold red]{counts.get('critical', 0)}[/bold red]  "
            f"[bold]High:[/bold] [red]{counts.get('high', 0)}[/red]  "
            f"[bold]Medium:[/bold] [yellow]{counts.get('medium', 0)}[/yellow]  "
            f"[bold]Low:[/bold] [cyan]{counts.get('low', 0)}[/cyan]"
        )
        console.print(Panel(summary_lines, title="[bold cyan]Scan Summary[/bold cyan]",
                            border_style=vuln_color, padding=(1, 2)))

        if not self.findings:
            console.print("\n[bold green]  ✓ No vulnerable subdomains detected. Domain appears clean.[/bold green]\n")
            return

        # ── Vulnerable Subdomains Table ─────────────────────────────────────
        console.print()
        console.rule("[bold red]Vulnerable Subdomains[/bold red]")
        console.print()

        table = Table(
            show_header=True,
            header_style="bold white on #1a1a2e",
            border_style="dim",
            show_lines=True,
            expand=True,
        )
        table.add_column("#",          width=4,  style="dim", justify="right")
        table.add_column("Subdomain",  min_width=24, no_wrap=False)
        table.add_column("Severity",   width=10, justify="center")
        table.add_column("Confidence", width=12, justify="center")
        table.add_column("Service",    width=22)
        table.add_column("Status",     width=10, justify="center")

        for i, f in enumerate(self.findings, 1):
            sev  = f.get("severity", "info")
            conf = f.get("confidence", "low")
            table.add_row(
                str(i),
                f"[bold]{f.get('subdomain', '')}[/bold]",
                self._severity_text(sev),
                self._confidence_text(conf),
                f.get("service", "Unknown"),
                str(f.get("status_code", "—")),
            )

        console.print(table)

        # ── Per-finding Detail Cards ────────────────────────────────────────
        console.print()
        console.rule("[bold yellow]Finding Details[/bold yellow]")

        for i, f in enumerate(self.findings, 1):
            sev   = f.get("severity", "info")
            conf  = f.get("confidence", "low")
            color = SEVERITY_COLORS.get(sev, "white")

            detail = (
                f"[bold]Subdomain:[/bold]   {f.get('subdomain', '')}\n"
                f"[bold]CNAME:[/bold]       {f.get('cname') or 'N/A'}\n"
                f"[bold]A Records:[/bold]   {', '.join(f.get('a_records', [])) or 'N/A'}\n"
                f"[bold]Service:[/bold]     {f.get('service', '')}\n"
                f"[bold]Severity:[/bold]    {self._severity_text(sev)}\n"
                f"[bold]Confidence:[/bold]  {self._confidence_text(conf)}\n"
                f"[bold]HTTP Status:[/bold] {f.get('status_code', '—')}\n\n"
                f"[bold]Description:[/bold]\n  {f.get('description', '')}\n\n"
                f"[bold green]Remediation:[/bold green]\n  {f.get('remediation', '')}\n\n"
                f"[bold blue]Reference:[/bold blue] {f.get('references', '')}"
            )

            console.print(Panel(
                detail,
                title=f"[{color}]Finding #{i} — {sev.upper()}[/{color}]",
                border_style=color.replace("bold ", ""),
                padding=(1, 2),
            ))

        # ── Remediation Summary ─────────────────────────────────────────────
        console.print()
        console.rule("[bold yellow]Remediation Summary[/bold yellow]")
        console.print()

        seen_rem = set()
        for f in self.findings:
            rem = f.get("remediation", "")
            svc = f.get("service", "")
            if rem and rem not in seen_rem:
                seen_rem.add(rem)
                console.print(f"  [bold cyan]{svc}:[/bold cyan]")
                console.print(f"    [dim]{rem}[/dim]\n")

        console.print()
