import re

class VulnerabilityAnalyzer:
    """
    Core engine for quantitative vulnerability assessment.
    Implements the M1-M4 mathematical model described in Section 3.
    """

    def __init__(self):
        # Threat severity mapping based on Section 3.4
        self.severity_scale = {
            "LOW": (0, 29),
            "MEDIUM": (30, 59),
            "HIGH": (60, 100)
        }

    def _calc_m1(self, profile):
        """Factor 1: Professional Role & Environment Exposure (Max 25)"""
        score = 0
        work_entries = profile.get("work", [])
        work_text = " ".join(work_entries).lower()
        contacts = profile.get("contacts", [])

        # 1.1 Job Details (Max 10)
        if work_entries:
            score += 3  # Company + general role
            if re.search(r'developer|engineer|manager|ceo|cto|founder|director|lead|specialist|accountant', work_text):
                score += 4
            if any(len(w) > 80 for w in work_entries):
                score += 3

        # 1.2 Employer Publicity (Max 5)
        if work_entries:
            score += 3  # Company clearly stated
            if re.search(r'startup|enterprise|inc\.|llc|corp|ltd', work_text):
                score += 2

        # 1.3 Contacts (Max 10)
        contacts_text = " ".join(contacts).lower()
        if '@' in contacts_text:
            score += 6  # Email found
        if re.search(r't\.me|skype|whatsapp', contacts_text):
            score += 4  # Messenger found

        return min(25, score)

    def _calc_m2(self, profile):
        """Factor 2: Socio-Psychological Context (Max 25)"""
        score = 0
        family_entries = profile.get("exposed_family", [])
        locations = profile.get("location", [])
        
        # 2.1 Family (Max 10)
        if family_entries:
            score += 3  
            score += 5  
            if any("url:" in f.lower() for f in family_entries):
                score += 2  

        # 2.2 Geolocation (Max 9)
        if locations:
            score += 2  
            if profile.get("education"):
                score += 3  
            loc_text = " ".join(locations).lower()
            if re.search(r'st\.|street|ave|blvd|apt|вул\.|просп\.', loc_text):
                score += 4  

        # 2.3 Profile Openness (Max 6)
        score += 4 
        if profile.get("latest_post_date") or len(profile.get("posts", [])) > 0:
            score += 2  

        return min(25, score)

    def _calc_m3(self, profile):
        """Factor 3: Technical Exposure & Identity (Max 25)"""
        score = 0
        tech = profile.get("tech_stack", [])
        tech_text = " ".join(tech).lower()
        
        # 3.1 Tech Stack (Max 10)
        if tech:
            score += 2  
            if re.search(r'react|vue|angular|django|flask|node|sql|mongo|postgres', tech_text):
                score += 3  
            if re.search(r'aws|docker|kubernetes|k8s|ci/cd|terraform|shell|linux|azure', tech_text):
                score += 5  

        # 3.2 Public Projects (Max 10)
        repos = profile.get("repo_count", 0)
        if repos > 3:
            score += 4
        elif repos > 0:
            score += 2
            
        if profile.get("stars_count", 0) > 10:
            score += 6

        # 3.3 Digital Identifiers (Max 5)
        if profile.get("nickname"):
            score += 1
        if len(profile.get("platforms", [])) >= 2:
            score += 4

        return min(25, score)

    def _calc_m4(self, profile):
        """Factor 4: Social Graph Depth (Max 25)"""
        score = 0
        
        # 4.1 Network Size (Max 12)
        friends = max([
            profile.get("friends_count", 0), 
            profile.get("connections_count", 0), 
            profile.get("followers_count", 0)
        ])
        if friends > 0:
            score += 5
        if friends > 100:
            score += 3
        if friends >= 500:
            score += 4

        # 4.2 Work/Education History (Max 7)
        if profile.get("past_jobs_count", 0) >= 2 or len(profile.get("work", [])) >= 2:
            score += 4
            
        edu_text = " ".join(profile.get("education", []))
        if re.search(r'20\d{2}', edu_text):
            score += 3  

        # 4.3 Activity & Endorsements (Max 6)
        if profile.get("has_endorsements", False):
            score += 3
            
        activity_text = profile.get("activity_text", "")
        contrib_match = re.search(r'([\d,]+)', activity_text)
        if contrib_match:
            contribs = int(contrib_match.group(1).replace(',', ''))
            if contribs > 100:
                score += 3

        return min(25, score)

    def _determine_severity(self, total_score):
        for severity, (low, high) in self.severity_scale.items():
            if low <= total_score <= high:
                return severity
        return "UNKNOWN"

    def analyze(self, profile):
        """Executes the risk evaluation pipeline."""
        # calc score
        m1 = self._calc_m1(profile)
        m2 = self._calc_m2(profile)
        m3 = self._calc_m3(profile)
        m4 = self._calc_m4(profile)
        
        total_score = m1 + m2 + m3 + m4
        severity = self._determine_severity(total_score)
        
        # Output to the terminal
        print(f"      [~] M1 (Professional): {m1}/25")
        print(f"      [~] M2 (Psycho-Social): {m2}/25")
        print(f"      [~] M3 (Technical): {m3}/25")
        print(f"      [~] M4 (Social Graph): {m4}/25")

        # form findings
        findings = []
        if profile.get("work"):
            findings.append(f"career exposure (potential bec vector): {profile['work'][0][:80]}...")
        if profile.get("tech_stack"):
            findings.append(f"technology stack exposed: {', '.join(profile['tech_stack'])}")
        if profile.get("location"):
            findings.append(f"geolocation/origin data exposed: {' | '.join(profile['location'])}")
        if profile.get("exposed_family"):
            findings.append(f"trust anchors exposed: {profile['exposed_family'][0]}")

        #return all keys
        return {
            "target_name": profile.get("full_name", "Unknown"),
            "platforms": profile.get("platforms", []), 
            "score": total_score,
            "vulnerability_index": total_score, 
            "severity": severity,
            "severity_level": severity,
            "findings": findings,
            "attack_vectors": findings
        }