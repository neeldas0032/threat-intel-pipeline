"""Vulnerability prioritization scoring engine."""
from threatintel.config import settings


def calculate_priority(on_kev: bool, epss: float, cvss: float) -> float:
    """Compute a 0-100 priority score from KEV status, EPSS probability, and CVSS severity.

    KEV entries are an override (always 100) — active exploitation outranks any
    theoretical severity. Otherwise, blend normalized EPSS and CVSS by the
    configured weights.

    Args:
        on_kev: True if the CVE is on the CISA KEV (actively exploited) list.
        epss:   Exploitation probability, 0.0-1.0.
        cvss:   Severity base score, 0.0-10.0.

    Returns:
        Priority score, 0.0-100.0. Higher = patch sooner.
    """
    if on_kev:
        return 100.0

    epss_norm = epss                 # already 0-1
    cvss_norm = cvss / 10.0          # 0-10 -> 0-1

    blended = (epss_norm * settings.weight_epss) + (cvss_norm * settings.weight_cvss)
    return round(blended * 100, 1)