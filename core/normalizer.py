import re

class DataNormalizer:
    """
    class for aggregating, deduplicating, and standardizing osint data 
    from multiple cross-platform sources into a single unified profile.
    """

    def __init__(self):
        self.unified_profile = {
            "primary_name": "",
            "platforms_analyzed": [],
            "unified_context": "", 
            "tech_stack": set(),
            "locations": set(),
            "social_anchors": set(),
            "raw_work_history": set()
        }

    def _clean_text(self, text: str) -> str:
        """
        removes extra whitespaces, newlines, and normalizes string format
        """
        if not text:
            return ""
        cleaned = re.sub(r'\s+', ' ', text)
        return cleaned.strip()

    def _merge_text_context(self, source_data: dict):
        """
        concatenates unstructured text fields (about, posts) into a single 
        semantic block for subsequent nlp processing
        """
        context_parts = []
        
        if "about" in source_data and source_data["about"]:
            context_parts.append(self._clean_text(source_data["about"]))
            
        if "posts" in source_data and isinstance(source_data["posts"], list):
            for post in source_data["posts"]:
                context_parts.append(self._clean_text(post))
                
        if context_parts:
            # appends new context to the existing unified context
            new_context = " ".join(context_parts)
            self.unified_profile["unified_context"] += f" {new_context}"

    def _extract_lists(self, source_data: dict):
        """
        extracts structured arrays (locations, tech stack, family) and 
        adds them to sets to automatically handle deduplication
        """
        if "location" in source_data:
            for loc in source_data["location"]:
                self.unified_profile["locations"].add(self._clean_text(loc))
                
        if "tech_stack" in source_data:
            for tech in source_data["tech_stack"]:
                self.unified_profile["tech_stack"].add(self._clean_text(tech))
                
        if "exposed_family" in source_data:
            for family_member in source_data["exposed_family"]:
                self.unified_profile["social_anchors"].add(self._clean_text(family_member))
                
        if "work" in source_data:
            for job in source_data["work"]:
                self.unified_profile["raw_work_history"].add(self._clean_text(job))

    def normalize(self, raw_profiles_list: list) -> dict:
        """
        iterates through a list of raw scraping results and fuses them 
        into a single standardized dictionary
        """
        for profile in raw_profiles_list:
            if not profile:
                continue
                
            platform = profile.get("platform", "Unknown")
            self.unified_profile["platforms_analyzed"].append(platform)
            
            # sets primary name from the first valid source
            if not self.unified_profile["primary_name"] and profile.get("full_name"):
                if profile["full_name"].lower() != "not found":
                    self.unified_profile["primary_name"] = self._clean_text(profile["full_name"])

            self._merge_text_context(profile)
            self._extract_lists(profile)

        # converts sets back to lists for json serialization compatibility
        self.unified_profile["tech_stack"] = list(self.unified_profile["tech_stack"])
        self.unified_profile["locations"] = list(self.unified_profile["locations"])
        self.unified_profile["social_anchors"] = list(self.unified_profile["social_anchors"])
        self.unified_profile["raw_work_history"] = list(self.unified_profile["raw_work_history"])
        
        # final cleanup of the unified text
        self.unified_profile["unified_context"] = self._clean_text(self.unified_profile["unified_context"])

        return self.unified_profile