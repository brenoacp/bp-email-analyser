from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "bp-email-analiser"
    API_PREFIX: str = "/api"
    NETWORK_TIMEOUT_SECONDS: float = 2.5
    MAX_HEADER_SIZE_BYTES: int = 1_000_000  # 1MB max

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
