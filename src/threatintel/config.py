"""Central configuration for the threat-intel pipeline, driven by env vars."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TI_", env_file=".env", extra="ignore")

    # --- API endpoints ---
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    epss_url: str = "https://api.first.org/data/v1/epss"

    # --- NVD tuning ---
    nvd_api_key: str | None = None          # set via TI_NVD_API_KEY; raises rate limit
    nvd_results_per_page: int = 20
    nvd_start_index: int = 371000           # TODO: replace hack with date-range pull
    request_timeout: int = 30               # seconds, applied to every HTTP call

    # --- Scoring weights (must sum to 1.0; validated below) ---
    weight_epss: float = 0.6
    weight_cvss: float = 0.4

    # --- Output ---
    output_csv: str = "threats.csv"
    # --- Database ---
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "threatintel"
    db_user: str = "postgres"
    db_password: str = "threatintel"

    def model_post_init(self, __context) -> None:
        total = self.weight_epss + self.weight_cvss
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"Scoring weights must sum to 1.0, got {total}")


settings = Settings()