from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite:///./attack_surface.db"

    # DNS TXT ownership verification (legal safeguard - see app/services/verification.py)
    verification_txt_prefix: str = "_platform-verify"

    # HaveIBeenPwned API (leak detection) - https://haveibeenpwned.com/API/Key
    hibp_api_key: str | None = None
    hibp_base_url: str = "https://haveibeenpwned.com/api/v3"

    # Alerting
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    alert_from_email: str = "alerts@example.com"
    slack_webhook_url: str | None = None

    # Scan behavior
    subfinder_binary: str = "subfinder"
    nmap_binary: str = "nmap"
    nmap_max_rate: int = 100  # packets/sec - conservative default, avoid anything resembling a DoS
    scan_common_ports: str = "21,22,25,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017"

    scan_interval_hours: int = 24


@lru_cache
def get_settings() -> Settings:
    return Settings()
