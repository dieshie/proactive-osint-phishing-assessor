import asyncio
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class GithubScraper:
    """
    class for extracting osint data from github public profiles
    with execution auditing.
    """

    def __init__(self, target_url):
        self.url = target_url
        self.results = {
            "platform": "GitHub",
            "full_name": "not found",
            "about": "",
            "location": [],
            "work": [],
            "tech_stack": [],
            "contacts": []
        }

    def _parse_profile_info(self, soup):
        # Name
        name_tag = soup.find('span', class_='p-name')
        if name_tag:
            self.results["full_name"] = name_tag.get_text().strip()
            print(f"    [+] identity data extracted: {self.results['full_name']}")

        # Bio/About
        bio_tag = soup.find('div', class_='p-note')
        if bio_tag:
            self.results["about"] = bio_tag.get_text().strip()
            print(f"    [+] bio/about extracted: {self.results['about'][:50]}...")

        # Work/Company
        org_tag = soup.find('span', class_='p-org')
        if org_tag:
            work_info = org_tag.get_text().strip()
            self.results["work"].append(work_info)
            print(f"    [+] career anchor found: {work_info}")

        # Location
        loc_tag = soup.find('span', class_='p-label')
        if loc_tag:
            loc_info = loc_tag.get_text().strip()
            self.results["location"].append(loc_info)
            print(f"    [+] location data extracted: {loc_info}")

    def _parse_tech_stack(self, soup):
        lang_tags = soup.find_all('span', itemprop='programmingLanguage')
        langs = [tag.get_text().strip() for tag in lang_tags]
        if langs:
            self.results["tech_stack"] = list(set(langs))
            print(f"    [+] tech stack identified: {', '.join(self.results['tech_stack'])}")

    async def run(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(self.url)
            
            try:
                await page.wait_for_selector('.vcard-names', timeout=5000)
            except:
                pass
            
            html_content = await page.content()
            soup = BeautifulSoup(html_content, 'html.parser')
            self._parse_profile_info(soup)
            self._parse_tech_stack(soup)
            await browser.close()
            return self.results