import asyncio
import re
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class FacebookScraper:
    """
    class for extracting osint data from facebook public profiles
    """

    def __init__(self, target_url, last_name):
        self.url = target_url
        self.last_name = last_name
        self.results = {
            "platform": "Facebook",
            "full_name": "Not found",
            "location": [],
            "status": [],
            "work": [],
            "posts": [],
            "exposed_family": []
        }

    async def _scroll_page(self, page, scrolls=3):
        """
        emulates mouse wheel scrolling to trigger lazy loading
        """
        for _ in range(scrolls):
            await page.mouse.wheel(0, 1000)
            await asyncio.sleep(2)

    def _parse_followers(self, soup, full_name):
        """
        identifies potential relatives by surname matching in followers list
        """
        relatives = []
        nodes = soup.find_all(['span', 'a'])
        
        for node in nodes:
            name = node.get_text(separator=" ").strip()
            # check if surname matches and exclude the target individual
            if self.last_name.lower() in name.lower():
                if len(name.split()) >= 2 and full_name.lower() not in name.lower():
                    # filtering out generic system labels
                    if not any(x in name.lower() for x in ["facebook", "friends"]):
                        relatives.append(name)
        return list(set(relatives))

    def _parse_main_content(self, soup):
        """
        extracts relationship status, career info, and locations via upward dom traversal
        """
        keywords = ["married", "у шлюбі", "works at", "працює в", "founder", "lives in", "живе в", "from", "родом з"]
        
        for kw in keywords:
            nodes = soup.find_all(string=re.compile(rf"{kw}", re.IGNORECASE))
            for node in nodes:
                parent = node.parent
                # upward traversal to capture context-rich parent elements
                for _ in range(3):
                    if parent.parent:
                        parent = parent.parent
                
                text = re.sub(r'\s+', ' ', parent.get_text().strip())
                if len(text) < 150:
                    if any(x in kw.lower() for x in ["works", "founder", "працює"]):
                        self.results["work"].append(text)
                    elif any(x in kw.lower() for x in ["lives", "from", "живе", "родом"]):
                        self.results["location"].append(text)
                    else:
                        self.results["status"].append(text)

    def _parse_posts(self, soup):
        """
        collects recent text-based posts for sentiment and behavioral analysis
        """
        text_blocks = soup.find_all(attrs={"dir": "auto"})
        for block in text_blocks:
            post_text = block.get_text(separator=" ").strip()
            # filtering for meaningful length and excluding UI controls
            if 40 < len(post_text) < 1000:
                ui_elements = ["Write a comment", "See translation", "Share", "Like", "Comment"]
                if not any(ui in post_text for ui in ui_elements):
                    self.results["posts"].append(post_text)
        self.results["posts"] = list(set(self.results["posts"]))[:3]

    async def run(self):
        """
        orchestrates the scraping process using playwright
        """
        async with async_playwright() as p:
            # launching browser in non-headless mode to handle potential interactions
            browser = await p.chromium.launch(headless=False, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            
            # primary profile page scan
            await page.goto(self.url)
            await page.wait_for_timeout(5000)
            await self._scroll_page(page, scrolls=2)
            
            main_html = await page.content()
            main_soup = BeautifulSoup(main_html, 'html.parser')
            
            # setting profile name from title
            title = main_soup.find('title')
            if title:
                self.results["full_name"] = title.get_text().replace("| Facebook", "").strip()

            self._parse_main_content(main_soup)
            self._parse_posts(main_soup)
            
            # followers list scan for relationship mapping
            await page.goto(f"{self.url}/followers")
            await page.wait_for_timeout(3000)
            await self._scroll_page(page, scrolls=3)
            
            followers_html = await page.content()
            followers_soup = BeautifulSoup(followers_html, 'html.parser')
            self.results["exposed_family"] = self._parse_followers(followers_soup, self.results["full_name"])
            
            await browser.close()
            return self.results