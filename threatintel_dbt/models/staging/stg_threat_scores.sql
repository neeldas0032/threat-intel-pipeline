select
    id,
    run_ts,
    cve_id,
    priority,
    on_kev,
    epss,
    cvss
from {{ source('raw', 'threat_scores') }}
