FROM apache/airflow:3.3.0

# Install the pipeline's Python dependencies into the Airflow image.
# dbt-postgres pulls in dbt-core; psycopg2-binary for the pipeline's storage layer.
USER airflow
RUN pip install --no-cache-dir \
    dbt-postgres==1.11.0 \
    psycopg2-binary==2.9.12 \
    pydantic-settings \
    requests