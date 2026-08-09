"""Threat-intel pipeline orchestration: ingest -> dbt run -> dbt test."""
from datetime import datetime

from airflow import DAG
from airflow.providers.standard.operators.bash import BashOperator

DBT_DIR = "/opt/airflow/threatintel_dbt"

with DAG(
    dag_id="threatintel_pipeline",
    description="Ingest CVEs, score them, then model and test with dbt.",
    schedule="@daily",
    start_date=datetime(2026, 8, 1),
    catchup=False,
    tags=["threat-intel"],
) as dag:

    ingest = BashOperator(
        task_id="ingest_and_score",
        bash_command="python -m threatintel.pipeline",
    )

    dbt_run = BashOperator(
        task_id="dbt_run",
        bash_command=f"cd {DBT_DIR} && dbt run --profiles-dir {DBT_DIR}",
    )

    dbt_test = BashOperator(
        task_id="dbt_test",
        bash_command=f"cd {DBT_DIR} && dbt test --profiles-dir {DBT_DIR}",
    )

    ingest >> dbt_run >> dbt_test