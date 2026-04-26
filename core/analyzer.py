import spacy

class VulnerabilityAnalyzer:
    """
    heuristic engine for semantic analysis and cyber risk scoring 
    based on aggregated osint profiles.
    """

    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            print("[!] error: nlp model not found. run: python -m spacy download en_core_web_sm")
            self.nlp = None

        self.weights = {
            "high_value_target": 25, 
            "tech_exposure": 20,     
            "social_trust": 20,      
            "corporate_vectors": 20, 
            "behavioral_triggers": 15 
        }

    def _evaluate_hvt_status(self, work_history: list) -> dict:
        """
        checks for high-value target (hvt) indicators in career history
        and lists ALL identified career vectors
        """
        hvt_keywords = ['ceo', 'founder', 'director', 'admin', 'devops', 'ciso', 'head', 'owner']
        result = {"score": 0, "findings": []}
        
        is_hvt = False
        all_jobs = []

        for job in work_history:
            all_jobs.append(job)
            if any(keyword in job.lower() for keyword in hvt_keywords):
                is_hvt = True

        if is_hvt:
            result["score"] = self.weights["high_value_target"]
            result["findings"].append(f"high-value target role identified in: {', '.join(all_jobs)}")
        elif all_jobs:
            # Якщо не HVT, але є місце роботи, все одно виводимо у звіт (без додаткових 25 балів)
            result["findings"].append(f"career exposure (potential bec vector): {', '.join(all_jobs)}")
                
        return result

    def _analyze_nlp_context(self, text: str, education_history: list) -> dict:
        """
        performs named entity recognition and integrates isolated academic data
        """
        result = {"score": 0, "findings": []}
        found_orgs = set()

        # 1. NLP Аналіз лише для пошуку корпорацій у чистому тексті
        if self.nlp and text:
            doc = self.nlp(text)
            for ent in doc.ents:
                # Беремо лише справжні ORG і фільтруємо сміттєві фрази
                if ent.label_ == "ORG" and len(ent.text) > 3 and len(ent.text) < 40:
                    found_orgs.add(ent.text)

        # 2. Додаємо чітко ізольовані дані про освіту (без багів злиття)
        for edu in education_history:
            found_orgs.add(edu)

        if found_orgs:
            result["score"] += self.weights["corporate_vectors"]
            orgs_str = " | ".join(list(found_orgs)[:4]) 
            result["findings"].append(f"corporate/academic entities exposed: {orgs_str}")

        # Пошук маркерів стресу
        stress_markers = ["urgent", "stress", "tired", "looking for new opportunities", "open to work"]
        if text and any(marker in text.lower() for marker in stress_markers):
            result["score"] += self.weights["behavioral_triggers"]
            result["findings"].append("emotional/behavioral stress markers detected")

        return result

    def _evaluate_technical_and_social(self, profile: dict) -> dict:
        """
        assesses technical exposure, social trust vectors, and ALL locations
        """
        result = {"score": 0, "findings": []}

        if profile.get("tech_stack"):
            result["score"] += self.weights["tech_exposure"]
            tech_str = ", ".join(profile["tech_stack"][:5])
            result["findings"].append(f"technology stack exposed: {tech_str}")

        if profile.get("social_anchors"):
            result["score"] += self.weights["social_trust"]
            anchors = ", ".join(profile["social_anchors"])
            result["findings"].append(f"trust anchors exposed: {anchors}")

        if profile.get("locations"):
            result["score"] += self.weights["behavioral_triggers"]
            locs = " | ".join(profile["locations"])
            result["findings"].append(f"geolocation/origin data exposed: {locs}")

        return result

    def _determine_severity(self, score: int) -> str:
        if score <= 25: return "LOW"
        if score <= 50: return "MEDIUM"
        if score <= 75: return "HIGH"
        return "CRITICAL"

    def analyze(self, unified_profile: dict) -> dict:
        final_score = 0
        all_findings = []

        hvt_eval = self._evaluate_hvt_status(unified_profile.get("raw_work_history", []))
        final_score += hvt_eval["score"]
        all_findings.extend(hvt_eval["findings"])

        # ПЕРЕДАЄМО ОСВІТУ В NLP-АНАЛІЗАТОР
        nlp_eval = self._analyze_nlp_context(
            unified_profile.get("unified_context", ""),
            unified_profile.get("education_history", [])
        )
        final_score += nlp_eval["score"]
        all_findings.extend(nlp_eval["findings"])

        tech_soc_eval = self._evaluate_technical_and_social(unified_profile)
        final_score += tech_soc_eval["score"]
        all_findings.extend(tech_soc_eval["findings"])

        bounded_score = min(100, final_score)

        return {
            "target_name": unified_profile.get("primary_name", "Unknown"),
            "platforms": unified_profile.get("platforms_analyzed", []),
            "vulnerability_score": bounded_score,
            "severity_level": self._determine_severity(bounded_score),
            "identified_vectors": all_findings
        }