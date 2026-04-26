import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

class VulnerabilityReporter:
    """
    class for generating structured console interfaces and exporting 
    analysis results into standardized json formats.
    """

    def __init__(self):
        self.console = Console()

    def display_banner(self):
        """
        renders the ascii art banner with a magnifying glass motif
        """
        magnifying_glass = """
[bold cyan]
      .--------.
    /          \\
   |   [white]OSINT[/white]    |
   |   [white]SCAN[/white]     |
    \\          /
      '--------'
           \\  \\
            \\  \\
             \\  \\
              \\__\\  [bold white]PROACTIVE CYBER THREAT DETECTION[/bold white]
                      [dim]automated vulnerability profiling engine[/dim]
        """
        self.console.print(Panel(magnifying_glass, border_style="blue", box=box.ROUNDED))

    def _get_severity_color(self, severity: str) -> str:
        """
        maps risk severity levels to console display colors
        """
        colors = {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "orange3",
            "CRITICAL": "bold red"
        }
        return colors.get(severity.upper(), "white")

    def display_report(self, analysis_result: dict):
        """
        builds and prints a formatted terminal table containing the analysis results
        """
        severity = analysis_result.get("severity_level", "UNKNOWN")
        score = analysis_result.get("vulnerability_score", 0)
        color = self._get_severity_color(severity)

        # creating the main summary table
        table = Table(title="[bold]TARGET VULNERABILITY PROFILE[/bold]", box=box.MINIMAL_DOUBLE_HEAD)
        
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        platforms_str = ", ".join(analysis_result.get("platforms", []))
        
        table.add_row("Target Name", f"[bold]{analysis_result.get('target_name', 'Unknown')}[/bold]")
        table.add_row("Platforms Analyzed", platforms_str)
        table.add_row("Vulnerability Index", f"[{color}]{score} / 100[/{color}]")
        table.add_row("Severity Level", f"[{color}][{severity}][/{color}]")
        
        self.console.print(table)
        self.console.print("\n[bold cyan]Identified Attack Vectors & Findings:[/bold cyan]")
        
        # printing specific findings
        findings = analysis_result.get("identified_vectors", [])
        if not findings:
            self.console.print("[green]  [+] no critical vulnerabilities identified.[/green]")
        else:
            for finding in findings:
                self.console.print(f"  [red][!][/red] {finding}")
        
        self.console.print("\n")

    def export_to_json(self, analysis_result: dict, unified_profile: dict, output_dir: str = "."):
        """
        saves the final unified report and normalized dataset to the filesystem 
        for record keeping and third-party siem integration.
        """
        target_name = analysis_result.get("target_name", "unknown_target").replace(" ", "_").lower()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/{target_name}_report_{timestamp}.json"

        # preparing metadata and rich data wrapper
        export_data = {
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "engine_version": "1.1" # Підняли версію через новий функціонал
            },
            "profile_analysis": analysis_result,
            "normalized_dataset": unified_profile # ДОДАНО: Повний набір очищених даних
        }

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=4, ensure_ascii=False)
            self.console.print(f"[dim]report successfully saved to {filename}[/dim]")
        except Exception as e:
            self.console.print(f"[bold red]error saving json report: {e}[/bold red]")