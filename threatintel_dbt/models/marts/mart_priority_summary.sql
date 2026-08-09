select
    run_ts,
    count(*) as total_cves,
    count(*) filter (where on_kev) as kev_count,
    count(*) filter (where priority >= 70) as critical_count,
    count(*) filter (where priority >= 40 and priority < 70) as high_count,
    count(*) filter (where priority >= 20 and priority < 40) as medium_count,
    count(*) filter (where priority < 20) as low_count,
    round(avg(priority)::numeric, 2) as avg_priority,
    max(priority) as max_priority
from {{ ref('stg_threat_scores') }}
group by run_ts
order by run_ts desc
