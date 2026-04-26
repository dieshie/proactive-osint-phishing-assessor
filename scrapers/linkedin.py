import asyncio
import re
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class LinkedinScraper:
    """
    enhanced linkedin scraper with dynamic auditing and improved public profile resilience.
    """

    def __init__(self, target_url):
        self.url = target_url
        self.results = {
            "platform": "LinkedIn",
            "full_name": "not found",
            "about": "",
            "location": [],
            "work": [],
            "education": [] # Додано для синхронізації з Facebook
        }

    async def _scroll_page(self, page, scrolls=3):
        for _ in range(scrolls):
            await page.mouse.wheel(0, 800)
            await asyncio.sleep(1.5)

    def _parse_header(self, soup):
        # Намагаємося знайти ім'я в різних тегах (h1 або специфічні класи)
        name_tag = soup.find('h1') or soup.find('title')
        if name_tag:
            name = name_tag.get_text().split('|')[0].strip()
            self.results["full_name"] = name
            print(f"    [+] professional identity: {self.results['full_name']}")

        # Пошук поточної посади
        headline = soup.find('div', class_=re.compile(r'text-body-medium|top-card-layout__headline', re.I))
        if headline:
            work_info = headline.get_text().strip()
            self.results["work"].append(work_info)
            print(f"    [+] career headline extracted: {work_info}")

    def _parse_sections(self, soup):
        text = soup.get_text(separator=' | ')
        target_name = self.results.get("full_name", "").lower()
        
        # Витягуємо локацію (з урахуванням коми для більшої точності)
        loc_match = re.search(r'([A-Z][a-z]+,?\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)?)', text)
        if loc_match:
            loc = loc_match.group(1).strip()
            # Перевіряємо: довжина > 3, це не слово LinkedIn, і це НЕ ім'я нашої цілі
            if len(loc) > 3 and "LinkedIn" not in loc and loc.lower() not in target_name:
                self.results["location"].append(loc)
                print(f"    [+] location data extracted: {loc}")

        # Пошук досвіду
        if "Experience" in text:
            print("    [+] experience section detected")
            
        # Пошук освіти
        if "Education" in text:
            edu_match = re.search(r'Education\s*\|\s*(.*?)\|', text, re.I)
            if edu_match:
                edu_info = edu_match.group(1).strip()
                # Додаємо перевірку, щоб не виводити порожні рядки
                if len(edu_info) > 4:
                    self.results["education"].append(edu_info)
                    print(f"    [+] academic data extracted: {edu_info}")

    async def run(self):
        async with async_playwright() as p:
            # Використовуємо headless=False для LinkedIn, щоб бачити, чи не вискочив логін-волл
            browser = await p.chromium.launch(headless=False, args=["--no-sandbox"])
            context = await browser.new_context()
            page = await context.new_page()
            
            await page.goto(self.url)
            await page.wait_for_timeout(6000) # Даємо час на рендеринг
            
            await self._scroll_page(page)
            
            html_content = await page.content()
            soup = BeautifulSoup(html_content, 'html.parser')
            
            self._parse_header(soup)
            self._parse_sections(soup)
            
            await browser.close()
            return self.results