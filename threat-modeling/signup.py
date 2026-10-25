# consent_api/auth.py
#
# The handler is the one from the article. enqueue_signup_task and load_secret
# are injectable here so it runs; wire them to your queue and secret store.
import hmac
import secrets
from collections.abc import Callable

from fastapi import APIRouter, FastAPI, Response, status
from pydantic import BaseModel, EmailStr

router = APIRouter()

# Replaced by create_app(); module-level so the handler reads like the article.
enqueue_signup_task: Callable[..., None] = lambda **_: None  # noqa: E731
load_secret: Callable[[str], str] = lambda name: ""  # noqa: E731


class SignupRequest(BaseModel):
    email: EmailStr
    phone: str


@router.post("/signup", status_code=status.HTTP_202_ACCEPTED)
def signup(req: SignupRequest, response: Response) -> dict:
    """
    LINDDUN: Detectability mitigation.
    DPDPA: S.8(5) reasonable safeguards.

    Always returns 202 Accepted with an opaque correlation ID.
    The actual account creation and notification happens asynchronously,
    so timing and status code cannot reveal whether the email/phone
    was already registered.
    """
    correlation_id = secrets.token_urlsafe(16)

    # Enqueue work; do not branch on "already exists" in the response path.
    # This is what removes the timing signal: the response does the same work
    # whether or not the account exists.
    enqueue_signup_task(
        correlation_id=correlation_id,
        email_hmac=_hmac(_normalise_email(req.email)),
        phone_hmac=_hmac(_normalise_phone(req.phone)),
    )

    return {"correlation_id": correlation_id, "status": "processing"}


def _normalise_email(email: str) -> str:
    # One person, one HMAC: "Asha@Example.in" and "asha@example.in" must match.
    return email.strip().lower()


def _normalise_phone(phone: str) -> str:
    digits = "".join(c for c in phone if c.isdigit())
    return digits[-10:] if len(digits) >= 10 else digits  # drop +91 / 0 prefixes


def _hmac(value: str) -> str:
    key = load_secret("SIGNUP_HMAC_KEY")  # from AWS KMS / HashiCorp Vault
    return hmac.new(key.encode(), value.encode(), "sha256").hexdigest()


def create_app(enqueue: Callable[..., None], secret_loader: Callable[[str], str]) -> FastAPI:
    global enqueue_signup_task, load_secret
    enqueue_signup_task, load_secret = enqueue, secret_loader
    app = FastAPI(title="Signup (reference)")
    app.include_router(router)
    return app
