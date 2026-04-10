from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List, Literal
from datetime import datetime


# ── AUTH ──────────────────────────────────────────────────────
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str


class EmailCheckRequest(BaseModel):
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyOtpRequest(BaseModel):
    email: EmailStr
    otp: str


class ResetPasswordWithOtpRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── SCANS ─────────────────────────────────────────────────────
class ScanCreate(BaseModel):
    target_url: str          # plain str — no Pydantic URL validation
    username: Optional[str]  = None
    password: Optional[str]  = None
    proxy_enabled: bool      = False
    proxy_url: Optional[str] = None
    proxy_type: Optional[str]= "http"
    verify_token: Optional[str] = None

    @field_validator("target_url")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target URL is required")
        # Auto-prefix scheme if missing
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        # Basic sanity check — must have a hostname after the scheme
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if not parsed.hostname:
            raise ValueError("URL must contain a valid hostname")
        return v


class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: str
    created_at: datetime
    total_risk_score: Optional[float] = 0.0

class ScanStepResponse(BaseModel):
    module_name: str
    module_key: str
    status: str
    severity: Optional[str]              = None
    risk_score: Optional[float]          = 0.0
    vulnerabilities: Optional[List[dict]]= []
    evidence: Optional[str]              = None
    remediation: Optional[str]           = None


class TargetVerifyRequest(BaseModel):
    target_url: str


class ProxySettingsUpdate(BaseModel):
    proxy_enabled: bool = False
    proxy_url: Optional[str] = None
    proxy_type: Optional[str] = "http"


class SubscriptionRequestCreate(BaseModel):
    plan: Literal["monthly", "yearly"] = "monthly"
    amount: float
    currency: str = "USD"
    transaction_id: str
    receipt_url: Optional[str] = None
    payment_method: Literal["upi", "debit_card", "crypto"] = "upi"
    upi_id: Optional[str] = None
    card_last4: Optional[str] = None
    crypto_network: Optional[str] = None
    crypto_wallet: Optional[str] = None

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("Amount must be greater than 0")
        return round(v, 2)

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, v: str) -> str:
        value = (v or "USD").strip().upper()
        if value not in {"USD", "INR"}:
            raise ValueError("Currency must be USD or INR")
        return value

    @field_validator("transaction_id")
    @classmethod
    def validate_transaction_id(cls, v: str) -> str:
        value = v.strip()
        if len(value) < 8:
            raise ValueError("Transaction ID must be at least 8 characters")
        return value

    @field_validator("receipt_url")
    @classmethod
    def normalize_receipt_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip()
        return value or None

    @field_validator("upi_id")
    @classmethod
    def normalize_upi_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip().lower()
        return value or None

    @field_validator("card_last4")
    @classmethod
    def normalize_card_last4(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        digits = "".join(ch for ch in v if ch.isdigit())
        return digits[-4:] if digits else None

    @field_validator("crypto_network", "crypto_wallet")
    @classmethod
    def normalize_crypto_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip()
        return value or None


class PaymentStatusUpdate(BaseModel):
    status: str  # pending, verified, rejected
    admin_note: Optional[str] = None


# ── MODULES ───────────────────────────────────────────────────
class ModuleUpdate(BaseModel):
    enabled: bool

class ModuleResponse(BaseModel):
    name: str
    module_key: str
    enabled: bool
    order: int


# ── ADMIN ─────────────────────────────────────────────────────
class RoleUpdate(BaseModel):
    role: str


class ScanLimitUpdate(BaseModel):
    scan_limit: int

    @field_validator("scan_limit")
    @classmethod
    def validate_scan_limit(cls, v: int) -> int:
        if v < 1 or v > 10000:
            raise ValueError("scan_limit must be between 1 and 10000")
        return v


class ModuleOrderUpdate(BaseModel):
    order: int

    @field_validator("order")
    @classmethod
    def validate_order(cls, v: int) -> int:
        if v < 1:
            raise ValueError("order must be a positive integer")
        return v