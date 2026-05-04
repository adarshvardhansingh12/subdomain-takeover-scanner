import dns.resolver
import requests
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()


class SubdomainEnumerator:
    """
    Enumerates subdomains using multiple sources for maximum coverage:
    1. crt.sh         — Certificate Transparency passive recon
    2. AlienVault OTX — Passive DNS (no API key needed)
    3. RapidDNS       — Fast passive subdomain database
    4. Subfinder      — If installed (Kali default), with generous timeout
    5. HackerTarget   — Backup passive source
    6. Wordlist       — Active DNS brute-force

    Each source gracefully fails and continues — one timeout won't kill the scan.
    Also detects DANGLING CNAMEs (CNAME exists but target doesn't resolve)
    which are the highest-value takeover candidates.
    """

    def __init__(self, domain: str, wordlist: str, threads: int = 20, timeout: int = 3):
        self.domain = (
            domain.strip().lower()
            .removeprefix("http://")
            .removeprefix("https://")
            .split("/")[0]
        )
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.found = []

    # ── Wordlist ──────────────────────────────────────────────────────────────

    def _load_wordlist(self) -> list[str]:
        try:
            with open(self.wordlist) as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            console.print(f"  [red]Wordlist not found: {self.wordlist}[/red]")
            return []

    # ── DNS Resolution ────────────────────────────────────────────────────────

    def _resolve_full(self, fqdn: str) -> dict | None:
        """
        Resolves a subdomain. Returns entry even if only CNAME exists
        (dangling DNS — the most critical takeover indicator).
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

            cname_target = None
            a_records = []
            is_dangling = False

            # Try CNAME first
            try:
                cname_ans = resolver.resolve(fqdn, "CNAME")
                cname_target = str(cname_ans[0].target).rstrip(".")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass

            # Try A record
            try:
                a_ans = resolver.resolve(fqdn, "A")
                a_records = [str(r) for r in a_ans]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                if cname_target:
                    is_dangling = True  # CNAME exists but nothing resolves = DANGLING
            except (dns.resolver.NoNameservers, dns.exception.Timeout):
                if cname_target:
                    is_dangling = True
            except Exception:
                pass

            if cname_target or a_records:
                return {
                    "subdomain": fqdn,
                    "cname": cname_target,
                    "a_records": a_records,
                    "is_dangling": is_dangling,
                    "source": "dns",
                }

        except Exception:
            pass
        return None

    # ── Passive Sources ───────────────────────────────────────────────────────

    def _fetch_crtsh(self) -> list[str]:
        """Certificate Transparency logs via crt.sh."""
        console.print(f"  [dim]crt.sh → querying {self.domain}...[/dim]")
        found = set()
        for attempt in range(2):  # retry once
            try:
                resp = requests.get(
                    f"https://crt.sh/?q=%.{self.domain}&output=json",
                    timeout=90,
                    headers={"User-Agent": "Mozilla/5.0 ReconStrike/1.0"},
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        break
                    for entry in data:
                        name = entry.get("name_value", "").strip().lower()
                        for sub in name.splitlines():
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(f".{self.domain}") or sub == self.domain:
                                if sub != self.domain:
                                    found.add(sub)
                    console.print(f"  [green]crt.sh:[/green] {len(found)} subdomains")
                    return list(found)
            except requests.exceptions.Timeout:
                console.print(f"  [yellow]crt.sh timed out (attempt {attempt+1}/2, waiting up to 90s), retrying...[/yellow]")
            except Exception as e:
                console.print(f"  [yellow]crt.sh failed: {type(e).__name__}[/yellow]")
                break
        console.print("  [yellow]crt.sh: skipped[/yellow]")
        return list(found)

    def _fetch_alienvault(self) -> list[str]:
        """AlienVault OTX — no API key needed, very reliable."""
        console.print(f"  [dim]AlienVault OTX → querying {self.domain}...[/dim]")
        found = set()
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0 ReconStrike/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    # strip wildcard prefix
                    hostname = hostname.lstrip("*.")
                    if self.domain in hostname and hostname != self.domain:
                        if hostname.endswith(self.domain):
                            found.add(hostname)
                console.print(f"  [green]AlienVault OTX:[/green] {len(found)} subdomains")
        except requests.exceptions.Timeout:
            console.print("  [yellow]AlienVault OTX: timed out, skipping[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]AlienVault OTX failed: {type(e).__name__}[/yellow]")
        return list(found)

    def _fetch_rapiddns(self) -> list[str]:
        """RapidDNS passive subdomain lookup."""
        console.print(f"  [dim]RapidDNS → querying {self.domain}...[/dim]")
        found = set()
        try:
            resp = requests.get(
                f"https://rapiddns.io/subdomain/{self.domain}?full=1",
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0 ReconStrike/1.0"},
            )
            if resp.status_code == 200:
                import re
                matches = re.findall(
                    rf'[\w\-\.]+\.{re.escape(self.domain)}', resp.text
                )
                for m in matches:
                    m = m.strip().lower()
                    if m.endswith(f".{self.domain}") and m != self.domain:
                        found.add(m)
                console.print(f"  [green]RapidDNS:[/green] {len(found)} subdomains")
        except requests.exceptions.Timeout:
            console.print("  [yellow]RapidDNS: timed out, skipping[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]RapidDNS failed: {type(e).__name__}[/yellow]")
        return list(found)

    def _fetch_subfinder(self) -> list[str]:
        """Use subfinder if available (Kali default). Generous timeout."""
        if not shutil.which("subfinder"):
            console.print("  [dim]subfinder: not installed, skipping[/dim]")
            return []

        console.print(f"  [dim]subfinder → scanning {self.domain}...[/dim]")
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent",
                 "-timeout", "60", "-t", "10"],
                capture_output=True,
                text=True,
                timeout=180,  # 3 minute hard limit
            )
            subs = [
                line.strip().lower()
                for line in result.stdout.splitlines()
                if line.strip() and line.strip().endswith(self.domain)
                and line.strip() != self.domain
            ]
            console.print(f"  [green]subfinder:[/green] {len(subs)} subdomains")
            return subs
        except subprocess.TimeoutExpired:
            console.print("  [yellow]subfinder: timed out after 3min, skipping[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]subfinder failed: {type(e).__name__}[/yellow]")
        return []

    def _fetch_hackertarget(self) -> list[str]:
        """HackerTarget API — backup source."""
        console.print(f"  [dim]HackerTarget → querying {self.domain}...[/dim]")
        found = set()
        try:
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                timeout=30,
                headers={"User-Agent": "Mozilla/5.0 ReconStrike/1.0"},
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.splitlines():
                    parts = line.split(",")
                    if parts and parts[0].strip().endswith(self.domain):
                        sub = parts[0].strip().lower()
                        if sub != self.domain:
                            found.add(sub)
                console.print(f"  [green]HackerTarget:[/green] {len(found)} subdomains")
        except requests.exceptions.Timeout:
            console.print("  [yellow]HackerTarget: timed out, skipping[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]HackerTarget failed: {type(e).__name__}[/yellow]")
        return list(found)

    # ── Batch Resolver ────────────────────────────────────────────────────────

    def _resolve_batch(self, fqdns: list[str]) -> list[dict]:
        """Resolve all FQDNs concurrently with progress bar."""
        if not fqdns:
            return []

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "  Resolving DNS...", total=len(fqdns)
            )
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._resolve_full, fqdn): fqdn
                    for fqdn in fqdns
                }
                for future in as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result:
                        results.append(result)
                        if result["is_dangling"]:
                            console.print(
                                f"  [bold red]DANGLING[/bold red] "
                                f"{result['subdomain']} → {result['cname']} "
                                f"[red](does not resolve!)[/red]"
                            )
                        else:
                            console.print(
                                f"  [green]LIVE[/green] {result['subdomain']} "
                                f"→ {result['cname'] or result['a_records']}"
                            )
        return results

    # ── Main Enumerate ────────────────────────────────────────────────────────

    def enumerate(self) -> list[dict]:
        all_fqdns: set[str] = set()

        # ── Passive sources ──────────────────────────────────────────────────
        console.rule("  [dim]Passive Enumeration[/dim]")

        sources = [
            ("crt.sh",         self._fetch_crtsh),
            ("AlienVault OTX", self._fetch_alienvault),
            ("RapidDNS",       self._fetch_rapiddns),
            ("subfinder",      self._fetch_subfinder),
            ("HackerTarget",   self._fetch_hackertarget),
        ]

        for name, fn in sources:
            try:
                subs = fn()
                before = len(all_fqdns)
                all_fqdns.update(subs)
                new = len(all_fqdns) - before
                if new > 0:
                    console.print(f"  [dim]+{new} new unique subdomains from {name}[/dim]")
            except Exception as e:
                console.print(f"  [yellow]{name} error: {e}[/yellow]")

        console.print(
            f"\n  [bold]Passive total:[/bold] {len(all_fqdns)} unique subdomains"
        )

        # ── Active brute-force ───────────────────────────────────────────────
        console.rule("  [dim]Active Brute-Force[/dim]")

        words = self._load_wordlist()
        if words:
            brute_fqdns = {f"{w}.{self.domain}" for w in words}
            new_from_brute = brute_fqdns - all_fqdns
            console.print(
                f"  [dim]Wordlist: {len(words)} words → "
                f"{len(new_from_brute)} new candidates to resolve[/dim]"
            )
            all_fqdns.update(brute_fqdns)

        console.print(
            f"\n  [bold]Total unique candidates:[/bold] {len(all_fqdns)}"
        )

        if not all_fqdns:
            console.print(
                "  [yellow]No candidates found. Check network connectivity "
                "or try without --no-bruteforce.[/yellow]"
            )
            return []

        # ── DNS Resolution ───────────────────────────────────────────────────
        console.rule("  [dim]DNS Resolution[/dim]")
        all_results = self._resolve_batch(list(all_fqdns))

        # ── Dangling CNAME summary ───────────────────────────────────────────
        dangling = [r for r in all_results if r.get("is_dangling")]
        if dangling:
            console.print(
                f"\n  [bold red]⚠  {len(dangling)} Dangling CNAMEs detected "
                f"— Critical takeover risk![/bold red]"
            )
            for d in dangling:
                console.print(
                    f"  [red]  → {d['subdomain']} "
                    f"CNAME → {d['cname']} (NXDOMAIN)[/red]"
                )

        console.print(
            f"\n  [bold]Enumeration complete.[/bold] "
            f"{len(all_results)} live/dangling subdomains found."
        )
        self.found = all_results
        return all_results
