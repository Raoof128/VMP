"""
Threat Intelligence Enrichment
Fetches CVE data from NVD, EPSS, and CISA KEV
"""

import os
import requests
from typing import Dict, Optional, List
from datetime import datetime
import time
import logging
import json

logger = logging.getLogger(__name__)


class NVDClient:
    """
    National Vulnerability Database (NVD) API client.

    Fetches CVSS scores and vulnerability details.
    API Key: https://nvd.nist.gov/developers/request-an-api-key
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.

        Args:
            api_key: NVD API key (recommended for higher rate limits)
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.base_url = os.getenv(
            "NVD_API_URL",
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VMP/1.0',
            'Accept': 'application/json'
        })

        if self.api_key:
            self.session.headers.update({'apiKey': self.api_key})

        # Rate limiting (without API key: 5 req/30s, with key: 50 req/30s)
        self.rate_limit_delay = 0.6 if self.api_key else 6.0

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch CVE details from NVD.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            Dictionary with CVE data or None if not found
        """
        try:
            url = f"{self.base_url}?cveId={cve_id}"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data.get('totalResults', 0) == 0:
                logger.warning(f"CVE not found in NVD: {cve_id}")
                return None

            cve_item = data['vulnerabilities'][0]['cve']

            # Extract CVSS data
            cvss_data = None
            cvss_v3 = cve_item.get('metrics', {}).get('cvssMetricV31', [])
            if cvss_v3:
                cvss_data = cvss_v3[0]['cvssData']
            else:
                # Try CVSS v3.0
                cvss_v3 = cve_item.get('metrics', {}).get('cvssMetricV30', [])
                if cvss_v3:
                    cvss_data = cvss_v3[0]['cvssData']

            # Extract CWE
            cwe_ids = []
            weaknesses = cve_item.get('weaknesses', [])
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('value', '').startswith('CWE-'):
                        cwe_ids.append(desc['value'])

            # Extract descriptions
            descriptions = cve_item.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break

            result = {
                'cve_id': cve_id,
                'description': description,
                'published_date': cve_item.get('published'),
                'last_modified': cve_item.get('lastModified'),
                'cvss_base_score': cvss_data.get('baseScore') if cvss_data else None,
                'cvss_severity': cvss_data.get('baseSeverity') if cvss_data else None,
                'cvss_vector': cvss_data.get('vectorString') if cvss_data else None,
                'cvss_version': cvss_data.get('version') if cvss_data else None,
                'cwe_ids': cwe_ids
            }

            logger.info(f"✓ Fetched NVD data for {cve_id}")

            # Rate limiting
            time.sleep(self.rate_limit_delay)

            return result

        except requests.RequestException as e:
            logger.error(f"Failed to fetch CVE from NVD: {e}")
            return None
        except (KeyError, IndexError, ValueError) as e:
            logger.error(f"Failed to parse NVD response: {e}")
            return None

    def get_cves_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Fetch multiple CVEs (sequential due to API limitations).

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to data
        """
        results = {}

        for cve_id in cve_ids:
            cve_data = self.get_cve(cve_id)
            if cve_data:
                results[cve_id] = cve_data

        return results


class EPSSClient:
    """
    EPSS (Exploit Prediction Scoring System) API client.

    Fetches exploit probability scores from FIRST.org.
    """

    def __init__(self, api_url: Optional[str] = None):
        """
        Initialize EPSS client.

        Args:
            api_url: Custom API URL
        """
        self.api_url = api_url or os.getenv(
            "EPSS_API_URL",
            "https://api.first.org/data/v1/epss"
        )
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VMP/1.0'})

    def get_epss_score(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch EPSS score for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            Dictionary with EPSS data or None
        """
        try:
            url = f"{self.api_url}?cve={cve_id}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()

            if 'data' in data and len(data['data']) > 0:
                result = data['data'][0]
                epss_data = {
                    'cve_id': cve_id,
                    'epss': float(result.get('epss', 0.0)),
                    'percentile': float(result.get('percentile', 0.0)),
                    'date': result.get('date')
                }

                logger.info(
                    f"✓ Fetched EPSS for {cve_id}: "
                    f"{epss_data['epss']:.1%} (percentile: {epss_data['percentile']:.1%})"
                )

                return epss_data

            logger.warning(f"No EPSS data found for {cve_id}")
            return None

        except requests.RequestException as e:
            logger.error(f"Failed to fetch EPSS score: {e}")
            return None
        except (KeyError, ValueError) as e:
            logger.error(f"Failed to parse EPSS response: {e}")
            return None

    def get_epss_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Fetch EPSS scores for multiple CVEs in batch.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to EPSS data
        """
        results = {}

        # EPSS API supports batch queries (up to 100 per request)
        chunk_size = 100

        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]

            try:
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

                logger.info(f"✓ Fetched EPSS data for {len(results)} CVEs")

            except requests.RequestException as e:
                logger.error(f"Failed to fetch EPSS batch: {e}")

        return results


class CISAKEVClient:
    """
    CISA Known Exploited Vulnerabilities (KEV) catalog client.

    Checks if vulnerabilities are actively exploited in the wild.
    """

    def __init__(self, catalog_url: Optional[str] = None):
        """
        Initialize CISA KEV client.

        Args:
            catalog_url: Custom catalog URL
        """
        self.catalog_url = catalog_url or os.getenv(
            "CISA_KEV_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VMP/1.0'})
        self._cache = None
        self._cache_timestamp = None

    def fetch_catalog(self, force_refresh: bool = False) -> Dict:
        """
        Fetch CISA KEV catalog.

        Args:
            force_refresh: Force refresh even if cached

        Returns:
            KEV catalog data
        """
        # Use cache if available and fresh (< 24 hours)
        if (not force_refresh and self._cache and self._cache_timestamp and
                (datetime.now() - self._cache_timestamp).seconds < 86400):
            return self._cache

        try:
            response = self.session.get(self.catalog_url, timeout=30)
            response.raise_for_status()

            self._cache = response.json()
            self._cache_timestamp = datetime.now()

            vuln_count = len(self._cache.get('vulnerabilities', []))
            logger.info(f"✓ Fetched CISA KEV catalog: {vuln_count} vulnerabilities")

            return self._cache

        except requests.RequestException as e:
            logger.error(f"Failed to fetch CISA KEV catalog: {e}")
            return {}

    def is_exploited(self, cve_id: str) -> bool:
        """
        Check if CVE is in CISA KEV catalog.

        Args:
            cve_id: CVE identifier

        Returns:
            True if CVE is known to be exploited
        """
        catalog = self.fetch_catalog()
        vulnerabilities = catalog.get('vulnerabilities', [])

        for vuln in vulnerabilities:
            if vuln.get('cveID') == cve_id:
                logger.info(f"⚠️  {cve_id} is in CISA KEV (actively exploited)")
                return True

        return False

    def get_exploited_cves(self) -> List[str]:
        """
        Get list of all exploited CVEs.

        Returns:
            List of CVE IDs in KEV catalog
        """
        catalog = self.fetch_catalog()
        vulnerabilities = catalog.get('vulnerabilities', [])

        return [v.get('cveID') for v in vulnerabilities if v.get('cveID')]


class ThreatIntelligenceEnricher:
    """
    Unified threat intelligence enrichment service.

    Combines NVD, EPSS, and CISA KEV data.
    """

    def __init__(self):
        """Initialize enrichment service"""
        self.nvd = NVDClient()
        self.epss = EPSSClient()
        self.cisa_kev = CISAKEVClient()

    def enrich_cve(self, cve_id: str) -> Dict:
        """
        Enrich CVE with data from all sources.

        Args:
            cve_id: CVE identifier

        Returns:
            Combined enrichment data
        """
        logger.info(f"Enriching {cve_id}...")

        enriched = {'cve_id': cve_id}

        # NVD data (CVSS, CWE, description)
        nvd_data = self.nvd.get_cve(cve_id)
        if nvd_data:
            enriched.update(nvd_data)

        # EPSS data (exploit probability)
        epss_data = self.epss.get_epss_score(cve_id)
        if epss_data:
            enriched['epss_score'] = epss_data['epss']
            enriched['epss_percentile'] = epss_data['percentile']

        # CISA KEV check
        enriched['in_cisa_kev'] = self.cisa_kev.is_exploited(cve_id)

        logger.info(f"✓ Enriched {cve_id} with threat intelligence")

        return enriched

    def enrich_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Enrich multiple CVEs efficiently.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to enriched data
        """
        logger.info(f"Enriching {len(cve_ids)} CVEs...")

        results = {}

        # Batch fetch EPSS (most efficient)
        epss_results = self.epss.get_epss_batch(cve_ids)

        # Sequential fetch NVD (API limitation)
        nvd_results = self.nvd.get_cves_batch(cve_ids)

        # Get KEV catalog once
        kev_cves = set(self.cisa_kev.get_exploited_cves())

        # Combine results
        for cve_id in cve_ids:
            enriched = {'cve_id': cve_id}

            if cve_id in nvd_results:
                enriched.update(nvd_results[cve_id])

            if cve_id in epss_results:
                enriched['epss_score'] = epss_results[cve_id]['epss']
                enriched['epss_percentile'] = epss_results[cve_id]['percentile']

            enriched['in_cisa_kev'] = cve_id in kev_cves

            results[cve_id] = enriched

        logger.info(f"✓ Enriched {len(results)} CVEs")

        return results


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test enrichment
    enricher = ThreatIntelligenceEnricher()

    # Test with Log4Shell
    print("\n" + "=" * 60)
    print("Testing Threat Intelligence Enrichment")
    print("=" * 60)

    cve_id = "CVE-2021-44228"  # Log4Shell
    data = enricher.enrich_cve(cve_id)

    print(f"\nEnriched data for {cve_id}:")
    print(f"  Description: {data.get('description', 'N/A')[:100]}...")
    print(f"  CVSS Score: {data.get('cvss_base_score', 'N/A')}")
    print(f"  CVSS Severity: {data.get('cvss_severity', 'N/A')}")
    print(f"  EPSS Score: {data.get('epss_score', 'N/A'):.1%}" if data.get('epss_score') else "  EPSS Score: N/A")
    print(f"  In CISA KEV: {data.get('in_cisa_kev', False)}")
    print(f"  CWE IDs: {', '.join(data.get('cwe_ids', []))}")

    print("\n" + "=" * 60)
