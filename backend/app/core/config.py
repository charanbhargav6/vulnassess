from pydantic_settings import BaseSettings

WEAK_KEYS = {
    "your-secret-key-change-in-production",
    "secret",
    "password",
    "changeme",
    "vulnassess-super-secret-key-2024-change-this",
}

class Settings(BaseSettings):
    APP_ENV: str = "development"
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "vulnassess"
    SECRET_KEY: str = ""
    CREDENTIALS_ENCRYPTION_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    AUTH_COOKIE_NAME: str = "va_session"
    AUTH_COOKIE_SECURE: bool = False
    AUTH_COOKIE_SAMESITE: str = "none"
    AUTH_COOKIE_DOMAIN: str = ""
    CSRF_TRUSTED_ORIGINS: str = ""

    # AI-powered remediation (Anthropic Claude)
    ANTHROPIC_API_KEY: str = ""

    # Email
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM: str = ""
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_PORT: int = 587

    # Frontend URL for CORS
    FRONTEND_URL: str = "http://localhost:3000"

    # Subscription duration
    SUBSCRIPTION_MONTH_DAYS: int = 30
    SUBSCRIPTION_YEAR_DAYS: int = 365

    # Scan restrictions
    BLOCKED_SCAN_HOSTS: str = "localhost,127.0.0.1,::1,0.0.0.0,metadata.google.internal"
    PROTECTED_OWN_HOSTS: str = "vulnassess.netlify.app,vulnassess-backend.onrender.com"

    class Config:
        env_file = ".env"
        extra = "ignore"

    def validate_security(self):
        """Fail fast if critical security settings are missing or weak."""
        is_production = self.APP_ENV.lower() in {"prod", "production"}

        if not self.SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY is not set. Add a strong random secret in your environment before starting the app."
            )
        if self.SECRET_KEY in WEAK_KEYS:
            raise RuntimeError(
                "SECRET_KEY is using an insecure default. Replace it with a strong random value before starting the app."
            )
        if is_production and not self.CREDENTIALS_ENCRYPTION_KEY:
            raise RuntimeError(
                "CREDENTIALS_ENCRYPTION_KEY is required in production. Set a generated Fernet key in your environment."
            )

settings = Settings()
settings.validate_security()