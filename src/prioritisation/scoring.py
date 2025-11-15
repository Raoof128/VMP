"""
Vulnerability Management Pipeline - Risk Scoring Engine
Implements business risk scoring combining CVSS, EPSS, and business context
"""

import os
import re
from typing import Dict, Optional, List
from datetime import datetime
import requests
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class RiskWeights:
    """
    Configurable weighting factors for risk score calculation.

    All weights must sum to 1.0 for normalized scoring.
    """
    cvss: float = float(os.getenv("RISK_WEIGHT_CVSS", "0.4"))
    epss: float = float(os.getenv("RISK_WEIGHT_EPSS", "0.3"))
    asset_criticality: float = float(os.getenv("RISK_WEIGHT_ASSET_CRITICALITY", "0.2"))
    remediation_difficulty: float = float(os.getenv("RISK_WEIGHT_REMEDIATION_DIFFICULTY", "0.1"))

    def __post_init__(self):
        """Validate that weights sum to 1.0"""
        total = self.cvss + self.epss + self.asset_criticality + self.remediation_difficulty
        if not (0.99 <= total <= 1.01):  # Allow small floating-point variance
            raise ValueError(f"Risk weights must sum to 1.0, got {total}")

    def validate(self):
        """Ensure all weights are between 0 and 1"""
        for field, value in self.__dict__.items():
            if not (0 <= value <= 1):
                raise ValueError(f"Weight '{field}' must be between 0 and 1, got {value}")


class RiskScorer:
    """
    Business Risk Scoring Engine

    Implements the formula:
    Business Risk Score (0–100) =
      (CVSS Base Score × weight_cvss) +
      (EPSS Score × weight_epss) +
      (Asset Criticality × weight_asset) +
      (Remediation Difficulty × weight_remediation)

    Then normalized to 0-100 scale.
    """

    def __init__(self, weights: Optional[RiskWeights] = None):
        """
        Initialize risk scorer with configurable weights.

        Args:
            weights: Custom RiskWeights instance, or None for defaults from environment
        """
        self.weights = weights or RiskWeights()
        self.weights.validate()

    def calculate_business_risk(
        self,
        cvss_base_score: float,
        epss_score: float,
        asset_criticality: float,
        remediation_difficulty: int
    ) -> Dict[str, float]:
        """
        Calculate business risk score with component breakdown.

        Args:
            cvss_base_score: CVSS base score (0.0 - 10.0)
            epss_score: EPSS probability (0.0 - 1.0)
            asset_criticality: Asset criticality (1 - 10)
            remediation_difficulty: Remediation effort (1 - 5)

        Returns:
            Dictionary with total score and component breakdowns

        Example:
            >>> scorer = RiskScorer()
            >>> result = scorer.calculate_business_risk(
            ...     cvss_base_score=8.5,
            ...     epss_score=0.75,
            ...     asset_criticality=9,
            ...     remediation_difficulty=2
            ... )
            >>> result['total_score']
            56.25
        """
        # Validate inputs
        self._validate_inputs(cvss_base_score, epss_score, asset_criticality, remediation_difficulty)

        # Calculate weighted components
        cvss_component = (cvss_base_score * self.weights.cvss)
        epss_component = (epss_score * self.weights.epss)
        asset_component = (asset_criticality * self.weights.asset_criticality)
        remediation_component = (remediation_difficulty * self.weights.remediation_difficulty)

        # Raw score (0-10 scale)
        raw_score = cvss_component + epss_component + asset_component + remediation_component

        # Normalize to 0-100 scale
        normalized_score = (raw_score / 10) * 100

        # Ensure score stays within bounds
        final_score = min(max(normalized_score, 0.0), 100.0)

        return {
            "total_score": round(final_score, 2),
            "components": {
                "cvss": round(cvss_component, 3),
                "epss": round(epss_component, 3),
                "asset_criticality": round(asset_component, 3),
                "remediation_difficulty": round(remediation_component, 3)
            },
            "raw_score": round(raw_score, 3),
            "explanation": self._generate_explanation(
                final_score, cvss_base_score, epss_score, asset_criticality, remediation_difficulty
            )
        }

    def _validate_inputs(
        self,
        cvss: float,
        epss: float,
        asset_criticality: float,
        remediation_difficulty: int
    ):
        """Validate input ranges"""
        if not (0 <= cvss <= 10):
            raise ValueError(f"CVSS score must be 0-10, got {cvss}")
        if not (0 <= epss <= 1):
            raise ValueError(f"EPSS score must be 0-1, got {epss}")
        if not (1 <= asset_criticality <= 10):
            raise ValueError(f"Asset criticality must be 1-10, got {asset_criticality}")
        if not (1 <= remediation_difficulty <= 5):
            raise ValueError(f"Remediation difficulty must be 1-5, got {remediation_difficulty}")

    def _generate_explanation(
        self,
        total_score: float,
        cvss: float,
        epss: float,
        asset_criticality: float,
        remediation_difficulty: int
    ) -> str:
        """Generate human-readable risk score explanation"""

        # Determine severity level
        if total_score >= 80:
            severity = "CRITICAL"
        elif total_score >= 60:
            severity = "HIGH"
        elif total_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Key risk factors
        factors = []
        if cvss >= 9.0:
            factors.append("severe technical vulnerability (CVSS ≥9.0)")
        if epss >= 0.7:
            factors.append("high exploit probability (EPSS ≥70%)")
        if asset_criticality >= 8:
            factors.append("critical asset (criticality ≥8)")
        if remediation_difficulty >= 4:
            factors.append("difficult remediation (effort ≥4)")

        factors_text = ", ".join(factors) if factors else "moderate risk factors"

        explanation = (
            f"Business Risk Score: {total_score}/100 ({severity} priority). "
            f"Key factors: {factors_text}. "
            f"Calculated from CVSS {cvss}, EPSS {epss:.1%}, "
            f"asset criticality {asset_criticality}/10, remediation effort {remediation_difficulty}/5."
        )

        return explanation

    def batch_calculate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Calculate risk scores for multiple vulnerabilities in batch.

        Args:
            vulnerabilities: List of dicts with required fields

        Returns:
            List of vulnerability dicts with added 'risk_score' field
        """
        results = []
        for vuln in vulnerabilities:
            try:
                score = self.calculate_business_risk(
                    cvss_base_score=vuln.get('cvss_base_score', 0.0),
                    epss_score=vuln.get('epss_score', 0.0),
                    asset_criticality=vuln.get('asset_criticality', 5.0),
                    remediation_difficulty=vuln.get('remediation_difficulty', 3)
                )
                vuln['risk_score'] = score
                results.append(vuln)
            except Exception as e:
                logger.error(f"Failed to score vulnerability {vuln.get('cve_id')}: {e}")
                vuln['risk_score'] = None
                results.append(vuln)

        return results


class CVSSParser:
    """
    CVSS (Common Vulnerability Scoring System) parser.

    Extracts base score and severity from CVSS v2, v3.0, v3.1 vectors.
    """

    CVSS_V3_REGEX = re.compile(
        r'CVSS:3\.[01]\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]'
    )

    SEVERITY_RANGES = {
        'CRITICAL': (9.0, 10.0),
        'HIGH': (7.0, 8.9),
        'MEDIUM': (4.0, 6.9),
        'LOW': (0.1, 3.9),
        'NONE': (0.0, 0.0)
    }

    @staticmethod
    def parse_vector(cvss_vector: str) -> Dict[str, any]:
        """
        Parse CVSS vector string into components.

        Args:
            cvss_vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")

        Returns:
            Dictionary with parsed components
        """
        if not cvss_vector:
            return {}

        components = {}
        parts = cvss_vector.split('/')

        # Extract version
        if parts[0].startswith('CVSS:'):
            components['version'] = parts[0].split(':')[1]

        # Parse metrics
        for part in parts[1:]:
            if ':' in part:
                metric, value = part.split(':')
                components[metric] = value

        return components

    @staticmethod
    def get_severity(cvss_score: float) -> str:
        """
        Determine severity level from CVSS base score.

        Args:
            cvss_score: CVSS base score (0.0 - 10.0)

        Returns:
            Severity level string
        """
        for severity, (min_score, max_score) in CVSSParser.SEVERITY_RANGES.items():
            if min_score <= cvss_score <= max_score:
                return severity
        return 'UNKNOWN'

    @staticmethod
    def validate_vector(cvss_vector: str) -> bool:
        """Validate CVSS v3.x vector format"""
        if not cvss_vector:
            return False
        return bool(CVSSParser.CVSS_V3_REGEX.match(cvss_vector))


class EPSSClient:
    """
    EPSS (Exploit Prediction Scoring System) API client.

    Fetches exploit probability scores from FIRST.org API.
    """

    def __init__(self, api_url: Optional[str] = None):
        """
        Initialize EPSS client.

        Args:
            api_url: Custom API URL, or None for default
        """
        self.api_url = api_url or os.getenv(
            "EPSS_API_URL",
            "https://api.first.org/data/v1/epss"
        )
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VMP/1.0'})

    def get_epss_score(self, cve_id: str) -> Optional[Dict[str, float]]:
        """
        Fetch EPSS score for a given CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            Dictionary with 'epss' and 'percentile', or None if not found

        Example:
            >>> client = EPSSClient()
            >>> score = client.get_epss_score("CVE-2021-44228")  # Log4Shell
            >>> score['epss']
            0.975
        """
        try:
            url = f"{self.api_url}?cve={cve_id}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()

            if 'data' in data and len(data['data']) > 0:
                result = data['data'][0]
                return {
                    'epss': float(result.get('epss', 0.0)),
                    'percentile': float(result.get('percentile', 0.0)),
                    'date': result.get('date')
                }

            logger.warning(f"No EPSS data found for {cve_id}")
            return None

        except requests.RequestException as e:
            logger.error(f"Failed to fetch EPSS for {cve_id}: {e}")
            return None
        except (KeyError, ValueError, IndexError) as e:
            logger.error(f"Failed to parse EPSS response for {cve_id}: {e}")
            return None

    def get_epss_batch(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        """
        Fetch EPSS scores for multiple CVEs in a single request.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to EPSS data
        """
        results = {}

        # EPSS API supports batch queries
        try:
            # Split into chunks of 100 (API limit)
            chunk_size = 100
            for i in range(0, len(cve_ids), chunk_size):
                chunk = cve_ids[i:i + chunk_size]
                cve_param = ','.join(chunk)

                url = f"{self.api_url}?cve={cve_param}"
                response = self.session.get(url, timeout=30)
                response.raise_for_status()

                data = response.json()

                if 'data' in data:
                    for item in data['data']:
                        cve = item.get('cve')
                        if cve:
                            results[cve] = {
                                'epss': float(item.get('epss', 0.0)),
                                'percentile': float(item.get('percentile', 0.0)),
                                'date': item.get('date')
                            }

        except requests.RequestException as e:
            logger.error(f"Failed to fetch EPSS batch: {e}")

        return results


# Example usage
if __name__ == "__main__":
    # Example 1: Calculate risk score
    scorer = RiskScorer()
    result = scorer.calculate_business_risk(
        cvss_base_score=8.5,
        epss_score=0.75,
        asset_criticality=9,
        remediation_difficulty=2
    )

    print("Business Risk Score Calculation:")
    print(f"Total Score: {result['total_score']}/100")
    print(f"Explanation: {result['explanation']}")
    print("\nComponent Breakdown:")
    for component, value in result['components'].items():
        print(f"  {component}: {value}")

    # Example 2: Parse CVSS vector
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    components = CVSSParser.parse_vector(cvss_vector)
    print(f"\nCVSS Vector: {cvss_vector}")
    print(f"Parsed Components: {components}")

    # Example 3: Fetch EPSS (requires internet)
    try:
        epss_client = EPSSClient()
        epss_data = epss_client.get_epss_score("CVE-2021-44228")  # Log4Shell
        if epss_data:
            print(f"\nLog4Shell EPSS Score: {epss_data['epss']:.1%}")
            print(f"Percentile: {epss_data['percentile']:.1%}")
    except Exception as e:
        print(f"\nEPSS fetch failed (expected without internet): {e}")
