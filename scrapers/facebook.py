import asyncio
import re
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class FacebookScraper:
    """
    Class for extracting OSINT data from Facebook public profiles.
    Updated to support the M1-M4 quantitative vulnerability assessment model.
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
            "education": [],
            "contacts": [],        # New: For Factor 1.3 (e-mails, messengers)
            "friends_count": 0     # New: For Factor 4.1 (network size)
        }

    async def _scroll_page(self, page, scrolls=3):
        """Emulates mouse wheel scrolling to trigger lazy loading."""
        for _ in range(scrolls):
            await page.mouse.wheel(0, 1000)
            await asyncio.sleep(2)

    def _parse_followers(self, soup, full_name):
        """Identifies potential relatives by surname matching in followers list."""
        relatives = []
        nodes = soup.find_all(['span', 'a'])
        
        for node in nodes:
            name = node.get_text(separator=" ").strip()
            if self.last_name.lower() in name.lower():
                if len(name.split()) >= 2 and full_name.lower() not in name.lower():
                    if not any(x in name.lower() for x in ["facebook", "friends"]):
                        # Factor 2.1: Extracting href links for relatives if available
                        link = ""
                        if node.name == 'a' and node.has_attr('href'):
                            link = f" [URL: {node['href'].split('?')[0]}]"
                        elif node.parent.name == 'a' and node.parent.has_attr('href'):
                            link = f" [URL: {node.parent['href'].split('?')[0]}]"
                            
                        relatives.append(name + link)
        return list(set(relatives))

    def _parse_main_content(self, soup):
        """
        Extracts relationship status, career info, locations, and education.
        Implements heuristics for Factors 1.1, 1.3, 2.1, 2.2, 4.1.
        """
        # Factor 1.3 & 4.1: Extracting Global Artifacts (Emails, Messengers, Friends Count)
        full_page_text = soup.get_text(separator=" ")
        
        # Regex for emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', full_page_text)
        if emails:
            self.results["contacts"].extend(list(set(emails)))
            print(f"    [+] contact vector (e-mail) exposed: {emails[0]}")

        # Regex for telegram/skype (basic heuristic)
        messengers = re.findall(r'(?:t\.me\/|skype:)[A-Za-z0-9_]{5,32}', full_page_text, re.IGNORECASE)
        if messengers:
            self.results["contacts"].extend(list(set(messengers)))
            print(f"    [+] contact vector (messenger) exposed: {messengers[0]}")

        # Regex for friends/followers count (Factor 4.1)
        friends_match = re.search(r'([\d,\.]+)[KkMm]?\s*(?:friends|followers|connections)', full_page_text, re.IGNORECASE)
        if friends_match:
            try:
                # Cleaning string like "1,200" or "1.5K" to integer
                raw_num = friends_match.group(1).replace(',', '')
                multiplier = 1
                if 'k' in friends_match.group(0).lower(): multiplier = 1000
                if 'm' in friends_match.group(0).lower(): multiplier = 1000000
                
                self.results["friends_count"] = int(float(raw_num) * multiplier)
                print(f"    [+] social graph metrics detected: ~{self.results['friends_count']} connections")
            except ValueError:
                pass

        # Contextual Extraction (Work, Location, Status)
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
                        
                        if len(text) > len(kw) + 3 and len(text) < 250: # Increased limit for detailed descriptions
                            # 1. Social tie (Factor 2.1)
                            if any(x in kw.lower() for x in ["married", "шлюб", "relationship"]):
                                # Attempt to find partner's profile link
                                partner_link = ""
                                link_tag = curr.find('a', href=True)
                                if link_tag:
                                    partner_link = f" [URL: {link_tag['href'].split('?')[0]}]"
                                
                                final_text = text + partner_link
                                print(f"    [+] social tie extracted: {final_text}")
                                self.results["exposed_family"].append(final_text)
                                
                            # 2. Career (Factor 1.1)
                            elif any(x in kw.lower() for x in ["works", "founder", "owner", "працює"]):
                                print(f"    [+] career data extracted: {text[:50]}...")
                                self.results["work"].append(text)
                                
                            # 3. Location (Factor 2.2)
                            elif any(x in kw.lower() for x in ["lives", "живе", "from", "родом", "born"]):
                                print(f"    [+] location data extracted: {text}")
                                self.results["location"].append(text)
                                
                            # 4. Education (Factor 4.2)
                            elif any(x in kw.lower() for x in ["studied", "university", "went", "college", "навчався"]):
                                print(f"    [+] academic data extracted: {text}")
                                self.results["education"].append(text)
                                
                            found_full_text = True
                            break
                if found_full_text:
                    break

    def _parse_posts(self, soup):
        """
        Collects recent posts and attempts to identify the date of the latest activity.
        Used for Factor 4.3 (Public Activity).
        """
        # Facebook often uses <span> or <a> for timestamps
        # We look for common patterns in post headers
        self.results["latest_post_date"] = None
        
        # Heuristic: Find elements that likely contain dates (e.g., "April 8", "12h", "Just now")
        # In FB, timestamps are often inside <span> tags within the post header
        potential_dates = soup.find_all(['span', 'a'], string=re.compile(r'(\d+\s*(?:h|m|d|hrs|mins|days)|January|February|March|April|May|June|July|August|September|October|November|December)', re.IGNORECASE))
        
        if potential_dates:
            # We take the first one found, as it's usually the most recent post at the top
            raw_date = potential_dates[0].get_text().strip()
            self.results["latest_post_date"] = raw_date
            print(f"    [+] activity detected: latest post around '{raw_date}'")

        # Original post text extraction logic
        text_blocks = soup.find_all(attrs={"dir": "auto"})
        for block in text_blocks:
            post_text = block.get_text(separator=" ").strip()
            if 40 < len(post_text) < 1000:
                ui_elements = ["Write a comment", "See translation", "Share", "Like", "Comment"]
                if not any(ui in post_text for ui in ui_elements):
                    self.results["posts"].append(post_text)
        
        self.results["posts"] = list(set(self.results["posts"]))[:3]

    async def run(self):
        """Orchestrates the scraping process using playwright."""
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

            self._parse_main_content(main_soup)
            self._parse_posts(main_soup)
            
            await page.goto(f"{self.url}/followers")
            await page.wait_for_timeout(3000)
            await self._scroll_page(page, scrolls=3)
            
            followers_html = await page.content()
            followers_soup = BeautifulSoup(followers_html, 'html.parser')
            
            followers_relatives = self._parse_followers(followers_soup, self.results["full_name"])
            self.results["exposed_family"].extend(followers_relatives)
            
            await browser.close()
            return self.results