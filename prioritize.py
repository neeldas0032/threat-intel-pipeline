def calculate_priority(on_kev: bool, epss: float, cvss: float) -> float:
    """
    Calculate a vulnerability's priority score from 0 to 100.

    Args:
        on_kev: True if the CVE is on the CISA KEV (actively exploited) list.
        epss:   Exploitation probability from EPSS, between 0.0 and 1.0.
        cvss:   Severity score from CVSS, between 0.0 and 10.0.

    Returns:
        A priority score between 0 and 100. Higher means patch sooner.
    """
    # RULE 1: If it's actively exploited, it's maximum priority — no debate.
    if on_kev:
        return 100.0

    # RULE 2: Otherwise, blend EPSS and CVSS on a common 0-1 scale.
    epss_normalized = epss              # already 0-1
    cvss_normalized = cvss / 10.0       # convert 0-10 scale to 0-1

    # Weights: exploitation likelihood (EPSS) matters more than raw severity.
    weight_epss = 0.6
    weight_cvss = 0.4

    blended = (epss_normalized * weight_epss) + (cvss_normalized * weight_cvss)

    # Scale to 0-100 for a readable priority number.
    return round(blended * 100, 1)


# --- Test the function with a few examples ---
print("KEV entry:      ", calculate_priority(on_kev=True,  epss=0.10, cvss=5.0))
print("High EPSS+CVSS: ", calculate_priority(on_kev=False, epss=0.97, cvss=9.8))
print("Your homework:  ", calculate_priority(on_kev=False, epss=0.50, cvss=6.0))
print("Low everything: ", calculate_priority(on_kev=False, epss=0.01, cvss=3.0))
print("KEV overrides:  ", calculate_priority(on_kev=True, epss=0.00, cvss=0.0))