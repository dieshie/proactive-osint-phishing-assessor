import logging
from typing import Dict, Any, Set

try:
    import spacy
except ImportError:
    spacy = None

class NlpEngine:
    """
    helper nlp layer to extract hidden entities (organizations, locations)
    from unstructured text artifacts.
    """

    def __init__(self):
        self.nlp = None
        if spacy:
            try:
                # load the small english model
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                logging.warning("[!] spacy model 'en_core_web_sm' not found. run: python -m spacy download en_core_web_sm")
        else:
            logging.warning("[!] spacy library not installed. nlp enrichment disabled.")

    def enrich(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        extracts named entities from profile texts and appends them if they are new.
        """
        # return original profile if nlp is not initialized
        if not self.nlp:
            return profile

        text_sources = []

        # safely extract 'about' section
        if profile.get("about") and isinstance(profile["about"], str):
            text_sources.append(profile["about"])

        # safely extract posts
        for post in profile.get("posts", []):
            if isinstance(post, str):
                text_sources.append(post)

        # safely extract work descriptions (handles both strings and dicts)
        for work_item in profile.get("work", []):
            if isinstance(work_item, str) and len(work_item) > 80:
                text_sources.append(work_item)
            elif isinstance(work_item, dict) and work_item.get("description"):
                if len(work_item["description"]) > 80:
                    text_sources.append(work_item["description"])

        # combine texts with a limit to maintain performance
        combined = " ".join(text_sources)[:8000]
        if not combined.strip():
            return profile

        # process the combined text
        doc = self.nlp(combined)

        new_orgs: Set[str] = set()
        new_locs: Set[str] = set()

        # extract named entities (orgs and geolocations)
        for ent in doc.ents:
            if ent.label_ == "ORG":
                new_orgs.add(ent.text.strip())
            elif ent.label_ == "GPE":
                new_locs.add(ent.text.strip())

        # build lowercased sets of existing data to avoid duplicates
        existing_orgs_lower = set()
        for w in profile.get("work", []):
            if isinstance(w, str):
                existing_orgs_lower.add(w.lower())
            elif isinstance(w, dict) and w.get("company"):
                existing_orgs_lower.add(w["company"].lower())

        existing_locs_lower = set()
        current_loc = profile.get("location")
        if isinstance(current_loc, str):
            existing_locs_lower.add(current_loc.lower())

        # append only new entities to the profile
        profile["nlp_orgs"] = [o for o in new_orgs if o.lower() not in existing_orgs_lower]
        profile["nlp_locations"] = [l for l in new_locs if l.lower() not in existing_locs_lower]

        return profile