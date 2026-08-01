"""Unit tests for the prioritization scoring engine."""
import pytest
from threatintel.scoring import calculate_priority


def test_kev_overrides_to_max():
    """A KEV entry is always 100, even with zero EPSS and CVSS."""
    assert calculate_priority(on_kev=True, epss=0.0, cvss=0.0) == 100.0


def test_kev_ignores_other_signals():
    """KEV override beats even a high non-KEV blend."""
    assert calculate_priority(on_kev=True, epss=0.1, cvss=5.0) == 100.0


def test_known_blend_case():
    """EPSS 0.5, CVSS 6.0 -> (0.5*0.6 + 0.6*0.4)*100 = 54.0."""
    assert calculate_priority(on_kev=False, epss=0.5, cvss=6.0) == 54.0


def test_high_but_not_kev_stays_below_100():
    """A nasty non-KEV CVE ranks high but never reaches the KEV ceiling."""
    score = calculate_priority(on_kev=False, epss=0.97, cvss=9.8)
    assert score == 97.4
    assert score < 100.0


def test_zero_everything():
    """No signal -> zero priority."""
    assert calculate_priority(on_kev=False, epss=0.0, cvss=0.0) == 0.0


def test_max_non_kev():
    """EPSS 1.0, CVSS 10.0, not on KEV -> 100.0 by blend (edge case)."""
    assert calculate_priority(on_kev=False, epss=1.0, cvss=10.0) == 100.0
    