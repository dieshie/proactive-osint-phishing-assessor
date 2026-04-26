import spacy

class VulnerabilityAnalyzer:
    """
    heuristic engine for semantic analysis and cyber risk scoring 
    based on aggregated osint profiles.
    """

    def __init__(self):
        # loading the nlp model for entity recognition
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            print("[!] error: nlp model not found. run: python -m spacy download en_core_web_sm")
            self.nlp = None

        # defining heuristic weights for risk calculation (max total: 100)
        self.weights = {
            "high_value_target": 25, # access to critical infrastructure or funds
            "tech_exposure": 20,     # exposed infrastructure details
            "social_trust": 20,      # exposed family or close connections
            "corporate_vectors": 20, # identified organizations for bec attacks
            "behavioral_triggers": 15 # locations or emotional stress markers
        }

    def _evaluate_hvt_status(self, work_history: list) -> dict:
        """
        checks for high-value target (hvt) indicators in career history
        """
        hvt_keywords = ['ceo', 'founder', 'director', 'admin', 'devops', 'ciso', 'head']
        result = {"score": 0, "findings": []}
        
        for job in work_history:
            if any(keyword in job.lower() for keyword in hvt_keywords):
                result["score"] = self.weights["high_value_target"]
                result["findings"].append(f"high-value target role identified: '{job}'")
                break # applied only once per category
                
        return result

    def _analyze_nlp_context(self, text: str) -> dict:
        """
        performs named entity recognition and semantic analysis on unstructured text
        """
        result = {"score": 0, "findings": []}
        if not self.nlp or not text:
            return result

        doc = self.nlp(text)
        found_orgs = set()
        
        # extracting corporate entities
        for ent in doc.ents:
            if ent.label_ == "ORG":
                found_orgs.add(ent.text)

        if found_orgs:
            result["score"] += self.weights["corporate_vectors"]
            orgs_str = ", ".join(list(found_orgs)[:3]) # keeping report concise
            result["findings"].append(f"corporate entities exposed (bec risk): {orgs_str}")

        # heuristic search for behavioral vulnerabilities
        stress_markers = ["urgent", "stress", "tired", "looking for new opportunities", "open to work"]
        if any(marker in text.lower() for marker in stress_markers):
            result["score"] += self.weights["behavioral_triggers"]
            result["findings"].append("emotional/behavioral stress markers detected")

        return result

    def _evaluate_technical_and_social(self, profile: dict) -> dict:
        """
        assesses technical exposure and social trust vectors
        """
        result = {"score": 0, "findings": []}

        # evaluating tech stack exposure
        if profile.get("tech_stack"):
            result["score"] += self.weights["tech_exposure"]
            tech_str = ", ".join(profile["tech_stack"][:3])
            result["findings"].append(f"technology stack exposed: {tech_str}")

        # evaluating social engineering anchors
        if profile.get("social_anchors"):
            result["score"] += self.weights["social_trust"]
            result["findings"].append(f"trust anchors (family/connections) exposed: {len(profile['social_anchors'])} identified")

        # evaluating location-based tracking
        if profile.get("locations") and not any("stress" in f for f in result["findings"]):
            # adding remaining behavioral points if location is found and stress wasn't
            result["score"] += self.weights["behavioral_triggers"]
            result["findings"].append(f"geolocation data exposed: {profile['locations'][0]}")

        return result

    def _determine_severity(self, score: int) -> str:
        """
        maps quantitative score to qualitative risk severity
        """
        if score <= 25: return "LOW"
        if score <= 50: return "MEDIUM"
        if score <= 75: return "HIGH"
        return "CRITICAL"

    def analyze(self, unified_profile: dict) -> dict:
        """
        main orchestration method that calculates final vulnerability index
        """
        final_score = 0
        all_findings = []

        # 1. role analysis (hvt)
        hvt_eval = self._evaluate_hvt_status(unified_profile.get("raw_work_history", []))
        final_score += hvt_eval["score"]
        all_findings.extend(hvt_eval["findings"])

        # 2. nlp context analysis
        nlp_eval = self._analyze_nlp_context(unified_profile.get("unified_context", ""))
        final_score += nlp_eval["score"]
        all_findings.extend(nlp_eval["findings"])

        # 3. tech and social analysis
        tech_soc_eval = self._evaluate_technical_and_social(unified_profile)
        final_score += tech_soc_eval["score"]
        all_findings.extend(tech_soc_eval["findings"])

        # ensuring score mathematically cannot exceed 100
        bounded_score = min(100, final_score)

        return {
            "target_name": unified_profile.get("primary_name", "Unknown"),
            "platforms": unified_profile.get("platforms_analyzed", []),
            "vulnerability_score": bounded_score,
            "severity_level": self._determine_severity(bounded_score),
            "identified_vectors": all_findings
        }