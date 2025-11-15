"""
Unit Tests for Risk Scoring Engine
Tests the business risk score calculation logic
"""

import pytest
from src.prioritisation.scoring import RiskScorer, RiskWeights, CVSSParser


class TestRiskScorer:
    """Test risk scoring calculations"""

    def test_critical_vulnerability_scoring(self):
        """CVSS 9.0, EPSS 0.9 on production asset should score >80"""
        scorer = RiskScorer()
        result = scorer.calculate_business_risk(
            cvss_base_score=9.0,
            epss_score=0.9,
            asset_criticality=10,
            remediation_difficulty=2
        )

        assert result['total_score'] > 80, f"Expected >80, got {result['total_score']}"
        assert result['total_score'] <= 100, "Score should not exceed 100"

    def test_low_vulnerability_scoring(self):
        """CVSS 3.0, EPSS 0.1 on dev asset should score <40"""
        scorer = RiskScorer()
        result = scorer.calculate_business_risk(
            cvss_base_score=3.0,
            epss_score=0.1,
            asset_criticality=2,
            remediation_difficulty=1
        )

        assert result['total_score'] < 40, f"Expected <40, got {result['total_score']}"
        assert result['total_score'] >= 0, "Score should not be negative"

    def test_log4shell_realistic_scoring(self):
        """CVE-2021-44228 (Log4Shell) should score as HIGH/CRITICAL"""
        scorer = RiskScorer()
        result = scorer.calculate_business_risk(
            cvss_base_score=10.0,
            epss_score=0.975,  # 97.5% exploit probability
            asset_criticality=9,
            remediation_difficulty=3
        )

        # Should be HIGH priority (60-79) or CRITICAL (80+)
        assert result['total_score'] >= 60, "Log4Shell should be HIGH/CRITICAL priority"
        assert 'CRITICAL' in result['explanation'] or 'HIGH' in result['explanation']

    def test_component_breakdown(self):
        """Verify component contributions are calculated correctly"""
        scorer = RiskScorer()
        result = scorer.calculate_business_risk(
            cvss_base_score=8.5,
            epss_score=0.75,
            asset_criticality=9,
            remediation_difficulty=2
        )

        # Check components exist
        assert 'components' in result
        assert 'cvss' in result['components']
        assert 'epss' in result['components']
        assert 'asset_criticality' in result['components']
        assert 'remediation_difficulty' in result['components']

        # Verify CVSS contribution (8.5 * 0.4 = 3.4)
        assert abs(result['components']['cvss'] - 3.4) < 0.01

    def test_invalid_cvss_score(self):
        """CVSS score outside 0-10 range should raise ValueError"""
        scorer = RiskScorer()

        with pytest.raises(ValueError, match="CVSS score must be 0-10"):
            scorer.calculate_business_risk(
                cvss_base_score=11.0,  # Invalid
                epss_score=0.5,
                asset_criticality=5,
                remediation_difficulty=3
            )

    def test_invalid_epss_score(self):
        """EPSS score outside 0-1 range should raise ValueError"""
        scorer = RiskScorer()

        with pytest.raises(ValueError, match="EPSS score must be 0-1"):
            scorer.calculate_business_risk(
                cvss_base_score=8.0,
                epss_score=1.5,  # Invalid
                asset_criticality=5,
                remediation_difficulty=3
            )

    def test_invalid_asset_criticality(self):
        """Asset criticality outside 1-10 range should raise ValueError"""
        scorer = RiskScorer()

        with pytest.raises(ValueError, match="Asset criticality must be 1-10"):
            scorer.calculate_business_risk(
                cvss_base_score=8.0,
                epss_score=0.5,
                asset_criticality=15,  # Invalid
                remediation_difficulty=3
            )

    def test_custom_weights(self):
        """Custom risk weights should affect scoring"""
        custom_weights = RiskWeights(
            cvss=0.5,
            epss=0.2,
            asset_criticality=0.2,
            remediation_difficulty=0.1
        )

        scorer = RiskScorer(weights=custom_weights)
        result = scorer.calculate_business_risk(
            cvss_base_score=8.0,
            epss_score=0.5,
            asset_criticality=5,
            remediation_difficulty=3
        )

        # With 50% CVSS weight, contribution should be 8.0 * 0.5 = 4.0
        assert abs(result['components']['cvss'] - 4.0) < 0.01

    def test_weights_sum_validation(self):
        """Risk weights must sum to 1.0"""
        with pytest.raises(ValueError, match="Risk weights must sum to 1.0"):
            RiskWeights(
                cvss=0.5,
                epss=0.3,
                asset_criticality=0.3,  # Sum = 1.1
                remediation_difficulty=0.1
            )

    def test_score_normalization_to_100(self):
        """Score should be normalized to 0-100 scale"""
        scorer = RiskScorer()

        # Maximum possible input
        result = scorer.calculate_business_risk(
            cvss_base_score=10.0,
            epss_score=1.0,
            asset_criticality=10,
            remediation_difficulty=5
        )

        # Should cap at 100
        assert result['total_score'] <= 100

    def test_explanation_generation(self):
        """Explanation should be human-readable"""
        scorer = RiskScorer()
        result = scorer.calculate_business_risk(
            cvss_base_score=9.0,
            epss_score=0.8,
            asset_criticality=9,
            remediation_difficulty=2
        )

        explanation = result['explanation']

        # Check explanation contains key info
        assert 'Business Risk Score' in explanation
        assert 'CVSS' in explanation
        assert 'EPSS' in explanation
        assert result['total_score'] >= 80  # Should be CRITICAL
        assert 'CRITICAL' in explanation


class TestCVSSParser:
    """Test CVSS parsing utilities"""

    def test_parse_cvss3_vector(self):
        """Parse CVSS v3.1 vector string"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        components = CVSSParser.parse_vector(vector)

        assert components['version'] == '3.1'
        assert components['AV'] == 'N'  # Network
        assert components['AC'] == 'L'  # Low complexity
        assert components['PR'] == 'N'  # No privileges required

    def test_severity_from_cvss_score(self):
        """Determine severity level from CVSS score"""
        assert CVSSParser.get_severity(9.5) == 'CRITICAL'
        assert CVSSParser.get_severity(7.5) == 'HIGH'
        assert CVSSParser.get_severity(5.0) == 'MEDIUM'
        assert CVSSParser.get_severity(2.0) == 'LOW'
        assert CVSSParser.get_severity(0.0) == 'NONE'

    def test_severity_boundary_conditions(self):
        """Test severity boundaries"""
        # Boundaries
        assert CVSSParser.get_severity(9.0) == 'CRITICAL'
        assert CVSSParser.get_severity(8.9) == 'HIGH'
        assert CVSSParser.get_severity(7.0) == 'HIGH'
        assert CVSSParser.get_severity(6.9) == 'MEDIUM'

    def test_validate_cvss_vector(self):
        """Validate CVSS v3.x vector format"""
        valid_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert CVSSParser.validate_vector(valid_vector) is True

        invalid_vector = "INVALID_CVSS_VECTOR"
        assert CVSSParser.validate_vector(invalid_vector) is False


class TestBatchScoring:
    """Test batch vulnerability scoring"""

    def test_batch_calculate(self):
        """Score multiple vulnerabilities in batch"""
        scorer = RiskScorer()

        vulnerabilities = [
            {
                'cve_id': 'CVE-2024-0001',
                'cvss_base_score': 9.0,
                'epss_score': 0.8,
                'asset_criticality': 9,
                'remediation_difficulty': 2
            },
            {
                'cve_id': 'CVE-2024-0002',
                'cvss_base_score': 5.0,
                'epss_score': 0.2,
                'asset_criticality': 5,
                'remediation_difficulty': 3
            }
        ]

        results = scorer.batch_calculate(vulnerabilities)

        assert len(results) == 2
        assert all('risk_score' in v for v in results)
        assert results[0]['risk_score']['total_score'] > results[1]['risk_score']['total_score']


# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance:
    """Test scoring performance"""

    @pytest.mark.performance
    def test_single_score_performance(self, benchmark):
        """Benchmark single vulnerability scoring"""
        scorer = RiskScorer()

        def score():
            return scorer.calculate_business_risk(
                cvss_base_score=8.5,
                epss_score=0.75,
                asset_criticality=9,
                remediation_difficulty=2
            )

        result = benchmark(score)
        # Should complete in milliseconds
        assert result['total_score'] > 0

    @pytest.mark.performance
    def test_batch_score_performance(self, benchmark):
        """Benchmark batch scoring of 1000 vulnerabilities"""
        scorer = RiskScorer()

        vulnerabilities = [
            {
                'cvss_base_score': 8.0,
                'epss_score': 0.5,
                'asset_criticality': 7,
                'remediation_difficulty': 3
            }
            for _ in range(1000)
        ]

        def batch_score():
            return scorer.batch_calculate(vulnerabilities)

        results = benchmark(batch_score)
        assert len(results) == 1000


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_zero_cvss_score(self):
        """Handle CVSS score of 0"""
        scorer = RiskScorer()
        result = scorer.calculate_business_risk(
            cvss_base_score=0.0,
            epss_score=0.0,
            asset_criticality=1,
            remediation_difficulty=1
        )

        assert result['total_score'] >= 0
        assert result['total_score'] < 40  # Should be LOW

    def test_maximum_values(self):
        """Handle maximum values for all inputs"""
        scorer = RiskScorer()
        result = scorer.calculate_business_risk(
            cvss_base_score=10.0,
            epss_score=1.0,
            asset_criticality=10,
            remediation_difficulty=5
        )

        assert result['total_score'] <= 100
        assert result['total_score'] >= 80  # Should be CRITICAL

    def test_minimum_asset_criticality(self):
        """Asset criticality minimum is 1, not 0"""
        scorer = RiskScorer()

        # Should accept criticality=1
        result = scorer.calculate_business_risk(
            cvss_base_score=5.0,
            epss_score=0.5,
            asset_criticality=1,  # Minimum
            remediation_difficulty=3
        )

        assert result['total_score'] >= 0

        # Should reject criticality=0
        with pytest.raises(ValueError):
            scorer.calculate_business_risk(
                cvss_base_score=5.0,
                epss_score=0.5,
                asset_criticality=0,  # Invalid
                remediation_difficulty=3
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.prioritisation.scoring"])
