import asyncio
import re
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class GithubScraper:
    """
    Class for extracting OSINT data from GitHub public profiles.
    Updated to support the quantitative M1-M4 vulnerability assessment model.
    """

    def __init__(self, target_url):
        self.url = target_url
        # Extracting username from URL for Factor 3.3 (Digital Identifiers)
        self.username = target_url.rstrip('/').split('/')[-1]
        
        self.results = {
            "platform": "GitHub",
            "full_name": "Not found",
            "nickname": self.username,
            "about": "",
            "location": [],
            "work": [],
            "tech_stack": [],
            "contacts": [],        # Factor 1.3 (Email, Twitter, etc.)
            "repo_count": 0,       # Factor 3.2 (Number of repos)
            "stars_count": 0,      # Factor 3.2 (Popularity)
            "followers_count": 0,  # Factor 4.1 (Network size)
            "activity_text": ""    # Factor 4.3 (Contributions)
        }

    def _clean_number(self, text_val):
        """Helper to convert '1.2k' or '1,234' into an integer."""
        text_val = text_val.lower().replace(',', '')
        if 'k' in text_val:
            return int(float(text_val.replace('k', '')) * 1000)
        try:
            return int(text_val)
        except ValueError:
            return 0

    def _parse_sidebar_identity(self, soup):
        """Extracts identity, work, location, contacts, and followers from the sidebar."""
        # Factor 1.1 & Identity
        name_tag = soup.find('span', class_='p-name')
        if name_tag:
            self.results["full_name"] = name_tag.get_text().strip()
            print(f"    [+] identity data extracted: {self.results['full_name']}")

        bio_tag = soup.find('div', class_='p-note')
        if bio_tag:
            self.results["about"] = bio_tag.get_text().strip()

        # Factor 1.2 & 1.1 (Work/Employer)
        org_tag = soup.find('span', class_='p-org')
        if org_tag:
            work_info = org_tag.get_text().strip()
            self.results["work"].append(work_info)
            print(f"    [+] career anchor found: {work_info}")

        # Factor 2.2 (Location)
        loc_tag = soup.find('span', class_='p-label')
        if loc_tag:
            loc_info = loc_tag.get_text().strip()
            self.results["location"].append(loc_info)

        # Factor 1.3 (Contacts: Email & Social Links)
        email_tag = soup.find('a', class_=re.compile(r'u-email', re.I))
        if email_tag:
            email = email_tag.get_text().strip()
            self.results["contacts"].append(email)
            print(f"    [+] contact vector exposed: {email}")

        # Finding other social links (Twitter, LinkedIn) in the sidebar
        social_links = soup.find_all('a', class_='Link--primary')
        for link in social_links:
            href = link.get('href', '')
            if any(x in href for x in ['twitter.com', 'linkedin.com', 't.me']):
                self.results["contacts"].append(href)

        # Factor 4.1 (Network Size - Followers)
        followers_tag = soup.find('a', href=re.compile(r'tab=followers'))
        if followers_tag:
            count_span = followers_tag.find('span', class_='text-bold')
            if count_span:
                self.results["followers_count"] = self._clean_number(count_span.get_text().strip())
                print(f"    [+] social graph metrics: {self.results['followers_count']} followers")

    def _parse_repositories_and_tech(self, soup):
        """Extracts tech stack, repository count, and star count for Factors 3.1 & 3.2."""
        # Total Repositories Count
        repo_tab = soup.find('a', id='repositories-tab')
        if repo_tab:
            counter = repo_tab.find('span', class_='Counter')
            if counter:
                self.results["repo_count"] = self._clean_number(counter.get('title', counter.get_text().strip()))
                print(f"    [+] technical exposure: {self.results['repo_count']} repositories found")

        # Tech Stack from Pinned Repos
        lang_tags = soup.find_all('span', itemprop='programmingLanguage')
        langs = [tag.get_text().strip() for tag in lang_tags]
        if langs:
            self.results["tech_stack"] = list(set(langs))
            print(f"    [+] tech stack identified: {', '.join(self.results['tech_stack'])}")

        # Calculate total stars on pinned repos to gauge popularity (Factor 3.2)
        pinned_items = soup.find_all('div', class_='pinned-item-list-item-content')
        total_pinned_stars = 0
        for item in pinned_items:
            # Looking for the star icon link
            star_link = item.find('a', href=re.compile(r'/stargazers'))
            if star_link:
                stars_text = star_link.get_text().strip()
                total_pinned_stars += self._clean_number(stars_text)
        
        self.results["stars_count"] = total_pinned_stars
        if total_pinned_stars > 0:
            print(f"    [+] project popularity: ~{total_pinned_stars} stars on pinned repos")

    def _parse_activity(self, soup):
        """
        Extracts contribution activity for Factor 4.3 using DOM-agnostic regex
        and cleans whitespace formatting.
        """
        full_text = soup.get_text(separator=" ")
        
        # Regex шукає патерн типу "6,123 contributions in the last year"
        contrib_match = re.search(r'([\d,]+)\s+contributions\s+in\s+the\s+last\s+year', full_text, re.IGNORECASE)
        
        if contrib_match:
            # Очищаємо від зайвих перенесень рядків та табуляцій
            activity_text = re.sub(r'\s+', ' ', contrib_match.group(0)).strip()
            self.results["activity_text"] = activity_text
            print(f"    [+] public activity detected: {activity_text}")
        else:
            # Альтернативний патерн
            alt_match = re.search(r'([\d,]+)\s+contributions', full_text, re.IGNORECASE)
            if alt_match:
                activity_text = re.sub(r'\s+', ' ', alt_match.group(0)).strip()
                self.results["activity_text"] = activity_text
                print(f"    [+] public activity detected (alt): {activity_text}")

    async def run(self):
        """Orchestrates the scraping process using playwright."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            
            await page.goto(self.url)
            
            # НОВЕ: Робимо невеликий скрол, щоб тригернути завантаження графіка активності
            await page.mouse.wheel(0, 800)
            await page.wait_for_timeout(2000) # Даємо 2 секунди на рендеринг SVG-графіка
            
            try:
                await page.wait_for_selector('.vcard-names', timeout=5000)
            except:
                pass
            
            html_content = await page.content()
            soup = BeautifulSoup(html_content, 'html.parser')
            
            self._parse_sidebar_identity(soup)
            self._parse_repositories_and_tech(soup)
            self._parse_activity(soup)
            
            await browser.close()
            return self.results