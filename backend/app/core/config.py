from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "bp-email-analiser"
    API_PREFIX: str = "/api"
    NETWORK_TIMEOUT_SECONDS: float = 2.5
    MAX_HEADER_SIZE_BYTES: int = 1_000_000  # 1MB max

    # Audit Logging Settings
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_LEVEL: str = "FULL"  # "FULL", "METADATA", "MINIMAL"
    AUDIT_LOG_FILE: str = "logs/audit.log"
    AUDIT_LOG_MAX_BYTES: int = 10_485_760  # 10MB
    AUDIT_LOG_BACKUP_COUNT: int = 5
    AUDIT_LOG_STDOUT: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
