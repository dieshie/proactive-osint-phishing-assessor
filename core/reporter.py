import json
import os
from datetime import datetime
from rich.console import Console

class VulnerabilityReporter:
    """
    Handles the formatting and exporting of the final quantitative vulnerability assessment.
    Generates terminal UI using 'rich' and JSON reports for SIEM integration.
    """
    def __init__(self):
        # Ініціалізуємо консоль rich для красивого виводу (як того очікує main.py)
        self.console = Console()

    def display_banner(self):
        """Displays the application startup banner."""
        self.console.print("\n[bold cyan]==========================================[/bold cyan]")
        self.console.print("[bold cyan]   PROACTIVE OSINT PHISHING ASSESSOR      [/bold cyan]")
        self.console.print("[bold cyan]==========================================[/bold cyan]\n")

    def display_report(self, analysis_result):
        """Prints the assessment table and findings to the terminal."""
        
        # Надійно витягуємо дані за новими ключами з analyzer.py
        score = analysis_result.get("score", 0)
        severity = analysis_result.get("severity", "UNKNOWN")
        target_name = analysis_result.get("target_name", "Unknown")
        
        # Захист від багу з "F, a, c, e, b, o, o, k"
        platforms = analysis_result.get("platforms", [])
        if isinstance(platforms, list):
            platforms_str = ", ".join(platforms)
        else:
            platforms_str = str(platforms)

        # Малюємо твою фірмову таблицю
        self.console.print("      [bold]TARGET VULNERABILITY PROFILE[/bold]        ")
        self.console.print("                      ╷                   ")
        self.console.print("  Metric              │ Value             ")
        self.console.print(" ═════════════════════╪══════════════════ ")
        self.console.print(f"  Target Name         │ [bold]{target_name}[/bold]")
        self.console.print(f"  Platforms Analyzed  │ {platforms_str}")
        self.console.print(f"  Vulnerability Index │ [bold white]{score} / 100[/bold white]")
        
        # Динамічний колір залежно від рівня загрози
        sev_color = "red" if severity in ["CRITICAL", "HIGH"] else "yellow" if severity == "MEDIUM" else "green"
        self.console.print(f"  Severity Level      │ [[bold {sev_color}]{severity}[/bold {sev_color}]]")
        self.console.print("                      ╵                   \n")

        # Вивід знайдених векторів атак
        self.console.print(" [bold]Identified Attack Vectors & Findings:[/bold]")
        findings = analysis_result.get("findings", [])
        if findings:
            for f in findings:
                # Обрізаємо занадто довгі тексти, щоб термінал не "ламався"
                safe_text = str(f).replace("\n", " ")[:150]
                if len(str(f)) > 150: safe_text += "..."
                self.console.print(f"  [bold red][!][/bold red] {safe_text}")
        else:
            self.console.print("  [bold green][+][/bold green] no critical vulnerabilities identified.")
        self.console.print("\n")

    def export_to_json(self, analysis_result, unified_profile, output_dir):
        """Saves the complete report and raw data to a JSON file."""
        target_name = analysis_result.get("target_name", "Unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = target_name.lower().replace(" ", "_")
        filepath = os.path.join(output_dir, f"{safe_name}_report_{timestamp}.json")
        
        # Пакуємо і бали, і всі сирі дані в один файл для диплома
        export_data = {
            "assessment": analysis_result,
            "raw_dataset": unified_profile
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=4, ensure_ascii=False)
            
        self.console.print(f"[dim]report successfully saved to {filepath}[/dim]\n")