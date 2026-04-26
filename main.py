import asyncio
import json
import os

from scrapers.facebook import FacebookScraper
from scrapers.github import GithubScraper
from scrapers.linkedin import LinkedinScraper
from core.normalizer import DataNormalizer
from core.analyzer import VulnerabilityAnalyzer
from core.reporter import VulnerabilityReporter

class OSINTCoordinator:
    """
    main orchestration class that manages the lifecycle of the osint profiling tool.
    handles data pipeline: scraping -> normalization -> analysis -> reporting.
    """

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.reporter = VulnerabilityReporter()
        self.analyzer = VulnerabilityAnalyzer()

    def _load_targets(self) -> list:
        """
        loads target profiles and their social links from a json configuration file
        """
        if not os.path.exists(self.config_path):
            self.reporter.console.print(f"[bold red]error: configuration file {self.config_path} not found.[/bold red]")
            return []
            
        with open(self.config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("targets", [])

    async def _execute_scrapers(self, target: dict) -> list:
        """
        asynchronously launches the appropriate scrapers based on available links
        """
        raw_results = []
        links = target.get("social_links", {})
        last_name = target.get("last_name", "Unknown")

        # formatting status output
        self.reporter.console.print(f"\n[bold yellow][*] initiating scan for target id: {target.get('id', 'unknown')}[/bold yellow]")

        # executing github scraper
        if links.get("github"):
            self.reporter.console.print("[dim] -> launching github module...[/dim]")
            gh_scraper = GithubScraper(links["github"])
            gh_data = await gh_scraper.run()
            raw_results.append(gh_data)

        # executing linkedin scraper
        if links.get("linkedin"):
            self.reporter.console.print("[dim] -> launching linkedin module...[/dim]")
            li_scraper = LinkedinScraper(links["linkedin"])
            li_data = await li_scraper.run()
            raw_results.append(li_data)

        # executing facebook scraper
        if links.get("facebook"):
            self.reporter.console.print("[dim] -> launching facebook module...[/dim]")
            fb_scraper = FacebookScraper(links["facebook"], last_name)
            fb_data = await fb_scraper.run()
            raw_results.append(fb_data)

        return raw_results

    async def run_pipeline(self):
        """
        main execution sequence
        """
        self.reporter.display_banner()
        targets = self._load_targets()

        if not targets:
            self.reporter.console.print("[red]no targets found to process. exiting.[/red]")
            return

        for target in targets:
            try:
                # 1. data extraction phase
                raw_profiles = await self._execute_scrapers(target)

                if not raw_profiles:
                    self.reporter.console.print("[yellow] [-] no data extracted for this target.[/yellow]")
                    continue

                # 2. data normalization phase
                self.reporter.console.print("[dim] -> fusing and normalizing cross-platform data...[/dim]")
                normalizer = DataNormalizer() # initialized per target to prevent data leakage
                unified_profile = normalizer.normalize(raw_profiles)

                # 3. semantic nlp analysis and heuristic scoring
                self.reporter.console.print("[dim] -> executing nlp and heuristic risk evaluation...[/dim]")
                analysis_result = self.analyzer.analyze(unified_profile)

                # 4. reporting phase
                self.reporter.display_report(analysis_result)
                
                # optional: exporting to local filesystem
                export_dir = "data/reports"
                os.makedirs(export_dir, exist_ok=True)
                # ОНОВЛЕНО: Передаємо unified_profile у генератор звітів
                self.reporter.export_to_json(analysis_result, unified_profile, output_dir=export_dir)

            except Exception as e:
                self.reporter.console.print(f"[bold red][!] critical pipeline error for target {target.get('id')}: {e}[/bold red]")

if __name__ == "__main__":
    # application entry point
    CONFIG_FILE = "data/targets.json"
    coordinator = OSINTCoordinator(CONFIG_FILE)
    
    # executing the async event loop
    asyncio.run(coordinator.run_pipeline())