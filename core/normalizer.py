class DataNormalizer:
    """
    Fuses data from multiple OSINT modules into a single Unified Profile.
    Updated to support all M1-M4 metrics (scalars, booleans, arrays) for 
    quantitative vulnerability assessment.
    """
    def __init__(self):
        self.unified_profile = {
            "full_name": "Unknown",
            "platforms": [],          # Tracks which scrapers succeeded (Factor 3.3)
            "about": "",
            
            # Arrays (M1, M2, M3, M4)
            "location": [],
            "work": [],
            "education": [],
            "posts": [],
            "exposed_family": [],
            "contacts": [],           # Emails, Messengers
            "tech_stack": [],         # Programming languages, frameworks
            
            # Scalars / Integers (M3, M4)
            "friends_count": 0,
            "connections_count": 0,
            "followers_count": 0,
            "repo_count": 0,
            "stars_count": 0,
            "past_jobs_count": 0,
            
            # Booleans (M4)
            "has_endorsements": False,
            
            # Strings
            "nickname": "",
            "activity_text": "",
            "latest_post_date": ""
        }

    def normalize(self, raw_results_list):
        """Merges a list of scraper result dictionaries into one."""
        #print("  -> fusing and normalizing cross-platform data...")
        
        for res in raw_results_list:
            if not res:
                continue
            
            # Record platform
            platform = res.get("platform")
            if platform and platform not in self.unified_profile["platforms"]:
                self.unified_profile["platforms"].append(platform)

            # Set name if not set
            if self.unified_profile["full_name"] == "Unknown" and res.get("full_name") not in ["Not found", "Unknown", None]:
                self.unified_profile["full_name"] = res.get("full_name")

            # 1. Merge Arrays (with deduplication to prevent noise)
            array_keys = ["location", "work", "education", "posts", "exposed_family", "contacts", "tech_stack"]
            for list_key in array_keys:
                if list_key in res and isinstance(res[list_key], list):
                    for item in res[list_key]:
                        if item not in self.unified_profile[list_key]:
                            self.unified_profile[list_key].append(item)

            # 2. Merge Integers (take the maximum value)
            int_keys = ["friends_count", "connections_count", "followers_count", "repo_count", "stars_count", "past_jobs_count"]
            for int_key in int_keys:
                if int_key in res and isinstance(res[int_key], int):
                    if res[int_key] > self.unified_profile[int_key]:
                        self.unified_profile[int_key] = res[int_key]

            # 3. Merge Booleans (Logical OR - if any platform has it, it's True)
            if res.get("has_endorsements"):
                self.unified_profile["has_endorsements"] = True

            # 4. Merge Strings (take if not empty)
            string_keys = ["nickname", "activity_text", "latest_post_date"]
            for str_key in string_keys:
                if str_key in res and res[str_key]:
                    self.unified_profile[str_key] = res[str_key]
                    
        return self.unified_profile