import asyncio
import re
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class FacebookScraper:
    """
    class for extracting osint data from facebook public profiles
    with execution auditing.
    """

    def __init__(self, target_url, last_name):
        self.url = target_url
        self.last_name = last_name
        self.results = {
            "platform": "Facebook",
            "full_name": "Not found",
            "about": "",
            "location": [],
            "work": [],
            "posts": [],
            "exposed_family": [],
            "education": []
        }

    async def _scroll_page(self, page, scrolls=3):
        for _ in range(scrolls):
            await page.mouse.wheel(0, 1000)
            await asyncio.sleep(2)

    def _parse_followers(self, soup, full_name):
        relatives = []
        nodes = soup.find_all(['span', 'a'])
        for node in nodes:
            name = node.get_text(separator=" ").strip()
            if self.last_name.lower() in name.lower():
                if len(name.split()) >= 2 and full_name.lower() not in name.lower():
                    if not any(x in name.lower() for x in ["facebook", "friends"]):
                        relatives.append(name)
        return list(set(relatives))

    def _parse_main_content(self, soup):
        """
        extracts relationship status, career info, locations, and education
        with dynamic console tracing.
        """
        keywords = [
            "married to", "у шлюбі", "relationship", "відносини", 
            "works at", "працює в", "founder", "owner", 
            "lives in", "живе в", "from", "родом з",
            "studied at", "навчався в", "went to", "university", "college",
            "born in", "народився в"
        ]
        
        for kw in keywords:
            nodes = soup.find_all(string=re.compile(rf"{kw}", re.IGNORECASE))
            for node in nodes:
                curr = node.parent
                found_full_text = False
                
                for _ in range(5):
                    if curr.parent:
                        curr = curr.parent
                        text = re.sub(r'\s+', ' ', curr.get_text(separator=" ").strip())
                        
                        if len(text) > len(kw) + 3 and len(text) < 150:
                            # 1. Сімейний статус -> йде у exposed_family
                            if any(x in kw.lower() for x in ["married", "шлюб", "relationship"]):
                                print(f"    [+] social tie extracted: {text}")
                                self.results["exposed_family"].append(text)
                                
                            # 2. Робота -> йде у work
                            elif any(x in kw.lower() for x in ["works", "founder", "owner", "працює"]):
                                print(f"    [+] career data extracted: {text}")
                                self.results["work"].append(text)
                                
                            # 3. Локація -> йде у location
                            elif any(x in kw.lower() for x in ["lives", "живе", "from", "родом", "born"]):
                                print(f"    [+] location data extracted: {text}")
                                self.results["location"].append(text)
                                
                            # 4. Освіта 
                            elif any(x in kw.lower() for x in ["studied", "university", "went", "college", "навчався"]):
                                print(f"    [+] academic data extracted: {text}")
                                self.results["education"].append(text) # ЗМІНЕНО З about
                                
                            found_full_text = True
                            break
                if found_full_text:
                    break

    def _parse_posts(self, soup):
        text_blocks = soup.find_all(attrs={"dir": "auto"})
        for block in text_blocks:
            post_text = block.get_text(separator=" ").strip()
            if 40 < len(post_text) < 1000:
                ui_elements = ["Write a comment", "See translation", "Share", "Like", "Comment"]
                if not any(ui in post_text for ui in ui_elements):
                    self.results["posts"].append(post_text)
        self.results["posts"] = list(set(self.results["posts"]))[:3]

    async def run(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            
            await page.goto(self.url)
            await page.wait_for_timeout(5000)
            await self._scroll_page(page, scrolls=2)
            
            main_html = await page.content()
            main_soup = BeautifulSoup(main_html, 'html.parser')
            
            title = main_soup.find('title')
            if title:
                self.results["full_name"] = title.get_text().replace("| Facebook", "").strip()

            # Викликаємо оновлені парсери
            self._parse_main_content(main_soup)
            self._parse_posts(main_soup)
            
            await page.goto(f"{self.url}/followers")
            await page.wait_for_timeout(3000)
            await self._scroll_page(page, scrolls=3)
            
            followers_html = await page.content()
            followers_soup = BeautifulSoup(followers_html, 'html.parser')
            
            # Додаємо родичів з фоловерів до загального списку
            followers_relatives = self._parse_followers(followers_soup, self.results["full_name"])
            self.results["exposed_family"].extend(followers_relatives)
            
            await browser.close()
            return self.results