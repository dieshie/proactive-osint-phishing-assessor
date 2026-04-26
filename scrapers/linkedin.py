import asyncio
import re
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class LinkedinScraper:
    """
    class for extracting osint data from linkedin professional profiles
    """

    def __init__(self, target_url):
        self.url = target_url
        self.results = {
            "platform": "LinkedIn",
            "full_name": "not found",
            "about": "",
            "location": [],
            "work": [],
            "education": []
        }

    async def _scroll_page(self, page, scrolls=4):
        """
        emulates user scrolling to trigger lazy loading of experience and about sections
        """
        for _ in range(scrolls):
            await page.mouse.wheel(0, 800)
            await asyncio.sleep(2)

    def _parse_header(self, soup):
        """
        extracts primary identity information from the top profile card
        """
        # extracts full name (usually within an h1 tag)
        name_tag = soup.find('h1')
        if name_tag:
            self.results["full_name"] = name_tag.get_text().strip()

        # extracts current headline/job title
        headline_tag = soup.find('div', class_=re.compile(r'text-body-medium', re.I))
        if headline_tag:
            self.results["work"].append(headline_tag.get_text().strip())

        # extracts geographical location
        loc_tag = soup.find('span', class_=re.compile(r'text-body-small inline t-black--light break-words', re.I))
        if loc_tag:
            self.results["location"].append(loc_tag.get_text().strip())

    def _parse_sections(self, soup):
        """
        extracts unstructured text from about and experience sections using heuristic markers
        """
        # linkedin often encrypts classes, so searching by section headers is more reliable
        page_text = soup.get_text(separator=' | ')
        
        # heuristic extraction for "about" section
        about_match = re.search(r'About\s*\|\s*(.*?)(?:\||Experience|Activity)', page_text, re.IGNORECASE | re.DOTALL)
        if about_match:
            cleaned_about = re.sub(r'\s+', ' ', about_match.group(1)).strip()
            if len(cleaned_about) > 20:
                self.results["about"] = cleaned_about

        # extracting specific experience entries by looking for common job titles and standard text flows
        experience_blocks = soup.find_all('div', class_=re.compile(r'pvs-list__outer-container', re.I))
        for block in experience_blocks:
            text = block.get_text(separator=" ").strip()
            cleaned_text = re.sub(r'\s+', ' ', text)
            if "yr" in cleaned_text or "mos" in cleaned_text: # markers for job duration
                self.results["work"].append(cleaned_text[:200]) # truncating to keep only relevant title/company info

    async def run(self):
        """
        orchestrates the scraping sequence and handles potential authentication walls
        """
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            
            await page.goto(self.url)
            
            # waits for 15 seconds to allow manual login or captcha resolution
            await page.wait_for_timeout(15000)
            
            # scrolls down to load dynamic blocks like experience and education
            await self._scroll_page(page)
            
            # expands "see more" buttons if they exist
            try:
                see_more_buttons = await page.locator("button:has-text('see more')").all()
                for btn in see_more_buttons:
                    await btn.click()
                    await asyncio.sleep(1)
            except Exception:
                pass # safely ignores if no expandable buttons are found

            html_content = await page.content()
            soup = BeautifulSoup(html_content, 'html.parser')
            
            self._parse_header(soup)
            self._parse_sections(soup)
            
            # data cleanup
            self.results["work"] = list(set(self.results["work"]))
            
            await browser.close()
            return self.results