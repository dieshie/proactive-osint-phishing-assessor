import asyncio
import re
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class LinkedinScraper:
    """
    Class for extracting OSINT data from LinkedIn profiles.
    Updated to support the quantitative M1-M4 vulnerability assessment model.
    """

    def __init__(self, target_url):
        self.url = target_url
        self.results = {
            "platform": "LinkedIn",
            "full_name": "Not found",
            "about": "",
            "location": [],
            "work": [],            # Current & past detailed jobs
            "past_jobs_count": 0,  # Factor 4.2
            "education": [],       # Factor 4.2
            "contacts": [],        # Factor 1.3
            "connections_count": 0,# Factor 4.1
            "has_endorsements": False, # Factor 4.3
            "skills": []           # Factor 3.1
        }

    async def _scroll_page(self, page):
        """Scrolls down slowly to trigger lazy loading of Experience and Skills sections."""
        for _ in range(5):
            await page.mouse.wheel(0, 800)
            await asyncio.sleep(1.5)

    def _clean_number(self, text_val):
        """Extracts integers from strings like '500+ connections'."""
        match = re.search(r'([\d,]+)', text_val)
        if match:
            clean_str = match.group(1).replace(',', '')
            return int(clean_str)
        return 0

    def _parse_profile(self, soup):
        """Extracts all M1-M4 metrics using DOM-agnostic heuristics with strict noise filtering."""
        full_text = soup.get_text(separator=" | ")

        # 1. Identity
        name_tag = soup.find('h1')
        target_name = ""
        if name_tag:
            target_name = name_tag.get_text().strip()
            self.results["full_name"] = target_name
            print(f"    [+] professional identity: {target_name}")

        # 2. Location extraction (Strict filtering)
        loc_match = re.search(r'([A-Z][a-z]+,?\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)?)\s*\|', full_text)
        if loc_match:
            loc = loc_match.group(1).strip()
            # Усі слова в нижньому регістрі для надійної фільтрації
            bad_words = ["linkedin", "top content", "profile", "activity", "search", "show all", "experience", "education"]
            if len(loc) > 3 and loc.lower() not in target_name.lower():
                if not any(bad in loc.lower() for bad in bad_words):
                    self.results["location"].append(loc)
                    print(f"    [+] location data extracted: {loc}")

        # 3. Network Size (Factor 4.1)
        conn_match = re.search(r'([\d,\+]+)\s*(?:connections|followers)', full_text, re.IGNORECASE)
        if conn_match:
            raw_conn = conn_match.group(1)
            self.results["connections_count"] = self._clean_number(raw_conn)
            print(f"    [+] social graph metrics: ~{self.results['connections_count']} connections")

        # 4. Contacts (Factor 1.3)
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', full_text)
        if emails:
            self.results["contacts"].extend(list(set(emails)))
            print(f"    [+] contact vector (e-mail) exposed: {emails[0]}")

        messengers = re.findall(r'(?:t\.me\/|@)[A-Za-z0-9_]{5,32}', full_text, re.IGNORECASE)
        if messengers:
            valid_msgs = [m for m in messengers if "linkedin" not in m.lower()]
            if valid_msgs:
                self.results["contacts"].extend(list(set(valid_msgs)))

        # 5. Work History & Descriptions (Factor 1.1 & 4.2)
        if "Experience" in full_text:
            print("    [+] experience section detected")
            job_dates = re.findall(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)?\s*\d{4}\s*[-–]\s*(?:Present|\d{4})', full_text, re.IGNORECASE)
            
            unique_jobs = list(set(job_dates))
            self.results["past_jobs_count"] = len(unique_jobs)
            if self.results["past_jobs_count"] > 0:
                print(f"    [+] career history: {self.results['past_jobs_count']} roles identified")

            paragraphs = soup.find_all(['span', 'p'])
            for p in paragraphs:
                p_text = p.get_text().strip()
                # Звузили діапазон та додали жорстку фільтрацію
                if 40 < len(p_text) < 400:
                    lower_text = p_text.lower()
                    # Відсікаємо UI елементи
                    ui_spam = ['cookie', 'agree to', 'join now', 'sign in', 'learn more', 'see more', 'reply', 'like', 'comment', 'repost', 'followers']
                    # Відсікаємо ознаки постів та відгуків (включаючи різні типи лапок та посилання)
                    is_post = any(char in p_text for char in ['#', 'http', 'www', '“', '”', '"', '✍️', '🚀', '👇'])
                    # Відсікаємо специфічні фрази з новинної стрічки
                    is_feed_chatter = any(word in lower_text for word in ['last week', 'yesterday', 'worked with', 'pleasure', 'thoughts?', 'i placed', 'we’re unlocking'])
                    
                    if not any(x in lower_text for x in ui_spam) and not is_post and not is_feed_chatter:
                        self.results["work"].append(p_text)

        # 6. Education (Factor 4.2)
        if "Education" in full_text:
            edu_match = re.search(r'Education\s*\|\s*(.*?)\|', full_text, re.I)
            if edu_match:
                edu_info = edu_match.group(1).strip()
                if len(edu_info) > 4:
                    self.results["education"].append(edu_info)
                    print(f"    [+] academic data extracted: {edu_info}")

        # 7. Skills & Endorsements (Factor 3.1 & 4.3)
        if re.search(r'(Skills|Endorsements|Recommendations)', full_text, re.IGNORECASE):
            self.results["has_endorsements"] = True
            print("    [+] public endorsements/skills section detected")

    async def run(self):
        """Orchestrates the scraping process."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            
            # Note: LinkedIn restricts unauthenticated views. We rely on what's visible publically.
            await page.goto(self.url)
            await page.wait_for_timeout(3000)
            
            # Scroll to load dynamic sections
            await self._scroll_page(page)
            
            html_content = await page.content()
            soup = BeautifulSoup(html_content, 'html.parser')
            
            self._parse_profile(soup)
            
            await browser.close()
            return self.results