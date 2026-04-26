import asyncio
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class GithubScraper:
    """
    class for extracting osint data from github public profiles
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
        """
        extracts basic profile information including bio, company, and location
        """
        # extracts full name
        name_tag = soup.find('span', class_='p-name')
        if name_tag:
            self.results["full_name"] = name_tag.get_text().strip()

        # extracts biography
        bio_tag = soup.find('div', class_='p-note')
        if bio_tag:
            self.results["about"] = bio_tag.get_text().strip()

        # extracts organization or company
        org_tag = soup.find('span', class_='p-org')
        if org_tag:
            self.results["work"].append(org_tag.get_text().strip())

        # extracts location
        loc_tag = soup.find('span', class_='p-label')
        if loc_tag:
            self.results["location"].append(loc_tag.get_text().strip())
            
        # extracts visible email addresses
        email_tag = soup.find('a', itemprop='email')
        if email_tag:
            self.results["contacts"].append(email_tag.get_text().strip())
            
        # extracts connected social links (e.g., twitter, linkedin)
        social_links = soup.find_all('a', rel='nofollow me')
        for link in social_links:
            self.results["contacts"].append(link.get('href'))

    def _parse_tech_stack(self, soup):
        """
        identifies programming languages and technologies from pinned repositories
        """
        lang_tags = soup.find_all('span', itemprop='programmingLanguage')
        for tag in lang_tags:
            self.results["tech_stack"].append(tag.get_text().strip())
            
        # removes duplicates to maintain clean data
        self.results["tech_stack"] = list(set(self.results["tech_stack"]))

    async def run(self):
        """
        orchestrates the scraping process for github profile using playwright
        """
        async with async_playwright() as p:
            # github allows headless crawling without aggressive blocking
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            
            await page.goto(self.url)
            
            # waits for the main profile container to ensure dom is loaded
            try:
                await page.wait_for_selector('.vcard-names', timeout=10000)
            except Exception:
                pass # proceeds even if selector times out (e.g., empty profile)
            
            html_content = await page.content()
            soup = BeautifulSoup(html_content, 'html.parser')
            
            self._parse_profile_info(soup)
            self._parse_tech_stack(soup)
            
            await browser.close()
            return self.results