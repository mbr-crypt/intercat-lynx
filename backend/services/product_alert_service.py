"""
Alerts for the products a user follows: in-app, e-mail and webhook.

A run (every few minutes, see ``tasks.send_product_alerts``) does this for each
user and each channel they enabled:

1. Find CVEs that concern a followed product, that Lynx learned about *after*
   the user started following that product (so following a product does not
   flood you with old CVEs) and within the last three days, that are severe
   enough (or actively exploited), and that were not sent over this channel yet.
2. Send them in batches. A batch that was delivered is written to
   ``notification_deliveries``; a failed one is not, so the next run tries again
   until the three days are over.

Webhook requests are signed (see ``sign``) and may not point at internal
networks unless the operator allows it (``WEBHOOK_ALLOW_PRIVATE_NETWORKS``),
otherwise a user could make the server probe the internal network (SSRF).
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    Notification,
    NotificationDelivery,
    NotificationSetting,
    User,
    Vulnerability,
    WatchedProduct,
)
from ..security.crypto import decrypt_secret, encrypt_secret
from . import watchlist_service as wl
from .email_service import email_service

logger = logging.getLogger(__name__)

CHANNELS = ("in_app", "email", "webhook")
WINDOW = timedelta(days=3)  # how long a missed or failed alert is still sent
MAX_PER_RUN = 100  # per user and channel; the rest follows in the next run
CHUNK = 25  # CVEs per e-mail / webhook call
WEBHOOK_TIMEOUT = 10


# --- settings --------------------------------------------------------------


def get_or_create_settings(db: Session, user: User) -> NotificationSetting:
    setting = (
        db.query(NotificationSetting).filter(NotificationSetting.user_id == user.id).first()
    )
    if setting is None:
        setting = NotificationSetting(user_id=user.id)
        db.add(setting)
        db.commit()
        db.refresh(setting)
    return setting


def new_webhook_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def _runtime(key: str, env: str, default: str = "") -> str:
    from .settings_service import runtime

    return str(runtime(key, env, default) or "")


def private_networks_allowed() -> bool:
    return _runtime("webhook.allow_private", "WEBHOOK_ALLOW_PRIVATE_NETWORKS", "false").lower() == "true"


# --- webhook safety ----------------------------------------------------------


def resolve_host(host: str) -> List[str]:
    """All addresses a host name points to (separate function so tests can replace it)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def _blocked(address: str, allow_private: bool) -> Optional[str]:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return None if allow_private else "internal network"
    # Never allowed, not even for operators: these are never a webhook receiver
    # and 169.254.169.254 is the cloud metadata service.
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "special address"
    # Private ranges, unique-local IPv6, carrier-grade NAT and the like
    if not ip.is_global and not allow_private:
        return "internal network"
    return None


def validate_webhook_url(url: str) -> None:
    """Raise ValueError (with a message for the user) if the URL may not be used."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Die Adresse muss mit http:// oder https:// beginnen.")
    if not parsed.hostname:
        raise ValueError("Die Adresse enthält keinen Rechnernamen.")
    if parsed.username or parsed.password:
        raise ValueError("Zugangsdaten in der Adresse sind nicht erlaubt.")
    try:
        addresses = resolve_host(parsed.hostname)
    except (socket.gaierror, UnicodeError):
        raise ValueError("Der Rechnername konnte nicht aufgelöst werden.")
    allow = private_networks_allowed()
    for address in addresses:
        reason = _blocked(address, allow)
        if reason == "internal network":
            raise ValueError(
                "Die Adresse liegt in einem internen Netz. Ein Administrator kann das mit "
                "WEBHOOK_ALLOW_PRIVATE_NETWORKS=true erlauben."
            )
        if reason:
            raise ValueError("Diese Adresse ist als Ziel nicht erlaubt.")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over ``<timestamp>.<body>``, hex. The timestamp stops replays."""
    message = timestamp.encode("ascii") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


# --- selecting what to send ----------------------------------------------------


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def candidates(
    db: Session,
    user: User,
    setting: NotificationSetting,
    channel: str,
    watches: Sequence[WatchedProduct],
    now: Optional[datetime] = None,
) -> List[Vulnerability]:
    """CVEs this user should get over ``channel`` that were not sent yet."""
    if not watches:
        return []
    now = now or datetime.now(timezone.utc)
    cutoff = now - WINDOW
    clauses = [
        and_(
            wl.watch_clause(w.vendor, w.product),
            Vulnerability.created_at >= max(_utc(w.created_at), cutoff),
        )
        for w in watches
    ]
    allowed = wl.severities_from(setting.min_severity) or wl.SEVERITIES
    severe = Vulnerability.severity.in_(allowed)
    if setting.always_exploited:
        severe = or_(severe, Vulnerability.exploited_in_the_wild.is_(True))

    already = db.query(NotificationDelivery.vulnerability_id).filter(
        NotificationDelivery.user_id == user.id, NotificationDelivery.channel == channel
    )
    return (
        db.query(Vulnerability)
        .filter(or_(*clauses), severe, ~Vulnerability.id.in_(already))
        .order_by(Vulnerability.created_at.asc(), Vulnerability.id.asc())
        .limit(MAX_PER_RUN)
        .all()
    )


def build_items(vulns: Iterable[Vulnerability], watches: Sequence[WatchedProduct]) -> List[dict]:
    base = _runtime("app.public_url", "PUBLIC_URL", "").rstrip("/")
    items = []
    for v in vulns:
        items.append(
            {
                "cve_id": v.cve_id,
                "title": v.simple_title or v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "published_at": v.published_at.isoformat() if v.published_at else None,
                "exploited_in_the_wild": bool(v.exploited_in_the_wild),
                "products": [wl.watch_label(w.vendor, w.product) for w in wl.matching_watches(v, watches)],
                "url": f"{base}/vulnerabilities/{v.cve_id}" if base else None,
            }
        )
    return items


# --- channels --------------------------------------------------------------------


def send_webhook(setting: NotificationSetting, user: User, items: List[dict], test: bool = False) -> Tuple[bool, Optional[str]]:
    """POST the items as JSON, signed. Returns (ok, error text without response body)."""
    if not setting.webhook_url or not setting.webhook_secret_encrypted:
        return False, "Webhook ist nicht eingerichtet"
    try:
        validate_webhook_url(setting.webhook_url)
        secret = decrypt_secret(setting.webhook_secret_encrypted)
    except ValueError as e:
        return False, str(e)

    now = datetime.now(timezone.utc)
    payload = {
        "event": "test" if test else "cve.new",
        "sent_at": now.isoformat(),
        "user": user.username,
        "items": items,
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(int(now.timestamp()))
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "InterCat-Lynx/0.1",
        "X-Lynx-Event": payload["event"],
        "X-Lynx-Delivery": str(uuid.uuid4()),
        "X-Lynx-Timestamp": timestamp,
        "X-Lynx-Signature": "sha256=" + sign(secret, timestamp, body),
    }
    try:
        # No redirects: a redirect could lead to an address we never checked
        response = requests.post(
            setting.webhook_url,
            data=body,
            headers=headers,
            timeout=WEBHOOK_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as e:
        return False, f"Senden fehlgeschlagen: {type(e).__name__}"
    if 200 <= response.status_code < 300:
        return True, None
    return False, f"Der Empfänger antwortete mit HTTP {response.status_code}"


def _email_text(user: User, items: List[dict]) -> Tuple[str, str, str]:
    count = len(items)
    exploited = sum(1 for i in items if i["exploited_in_the_wild"])
    subject = (
        f"InterCat Lynx: {count} neue Schwachstelle{'n' if count != 1 else ''}"
        + (f", {exploited} davon ausgenutzt" if exploited else "")
    )
    lines = [f"Hallo {user.full_name or user.username},", "", "für deine Produkte gibt es Neues:", ""]
    html = [
        f"<p>Hallo {_esc(user.full_name or user.username)},</p>",
        "<p>für deine Produkte gibt es Neues:</p><ul>",
    ]
    for i in items:
        score = f" {i['cvss_score']:.1f}" if i["cvss_score"] is not None else ""
        flag = " – AKTIV AUSGENUTZT" if i["exploited_in_the_wild"] else ""
        head = f"{i['cve_id']} [{i['severity'] or 'unbewertet'}{score}]{flag}"
        lines += [head, f"  {i['title']}", f"  Betrifft: {', '.join(i['products'])}"]
        if i["url"]:
            lines.append(f"  {i['url']}")
        lines.append("")
        link = f'<a href="{_esc(i["url"])}">{_esc(i["cve_id"])}</a>' if i["url"] else _esc(i["cve_id"])
        html.append(
            f"<li><strong>{link}</strong> [{_esc(i['severity'] or 'unbewertet')}{_esc(score)}]"
            f"{' – <strong>aktiv ausgenutzt</strong>' if i['exploited_in_the_wild'] else ''}<br>"
            f"{_esc(i['title'])}<br><small>Betrifft: {_esc(', '.join(i['products']))}</small></li>"
        )
    lines += ["Diese Meldungen kannst du in InterCat Lynx unter „Meine Produkte“ einstellen.", "", "InterCat Lynx"]
    html.append("</ul><p>Diese Meldungen kannst du in InterCat Lynx unter „Meine Produkte“ einstellen.</p>")
    return subject, "\n".join(lines), "".join(html)


def _esc(value: str) -> str:
    import html as _html

    return _html.escape(value or "", quote=True)


def send_email(user: User, items: List[dict]) -> Tuple[bool, Optional[str]]:
    """Really send (never just log): an alert that only reaches the log is worthless."""
    # Only to an address whose owner has proven the mailbox. Otherwise anyone
    # who can set an arbitrary address on an account could use this server to
    # send vulnerability mails to third parties.
    if not user.is_verified:
        return False, "Die E-Mail-Adresse ist noch nicht bestätigt"
    if not email_service.smtp_enabled:
        return False, "Der E-Mail-Versand ist auf diesem Server nicht eingerichtet"
    try:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        from_name, from_email = email_service._sender()
        if not from_email:
            return False, "Absenderadresse fehlt"
        subject, text, html = _email_text(user, items)
        msg = MIMEMultipart("alternative")
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = user.email
        msg["Subject"] = subject
        msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
        email_service._smtp_send(msg, user.email)
        return True, None
    except Exception as e:  # noqa: BLE001 - report any transport problem to the user
        return False, f"Senden fehlgeschlagen: {type(e).__name__}"


def deliver_in_app(db: Session, user: User, vulns: List[Vulnerability], watches: Sequence[WatchedProduct]) -> None:
    for v in vulns:
        names = ", ".join(wl.watch_label(w.vendor, w.product) for w in wl.matching_watches(v, watches))
        flag = " (aktiv ausgenutzt)" if v.exploited_in_the_wild else ""
        db.add(
            Notification(
                user_id=user.id,
                type="product_cve",
                title=f"{v.cve_id}{flag}",
                message=f"{v.simple_title or v.title} - betrifft {names}",
                cve_id=v.cve_id,
            )
        )


def _record(db: Session, user: User, vulns: List[Vulnerability], channel: str) -> None:
    for v in vulns:
        try:
            with db.begin_nested():
                db.add(NotificationDelivery(user_id=user.id, vulnerability_id=v.id, channel=channel))
        except IntegrityError:
            pass  # a parallel run was faster, fine


def sample_item() -> dict:
    base = _runtime("app.public_url", "PUBLIC_URL", "").rstrip("/")
    return {
        "cve_id": "CVE-0000-00000",
        "title": "Testnachricht von InterCat Lynx",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "published_at": datetime.now(timezone.utc).isoformat(),
        "exploited_in_the_wild": False,
        "products": ["Beispiel Produkt"],
        "url": f"{base}/watchlist" if base else None,
    }


def send_test(db: Session, user: User, setting: NotificationSetting, channel: str) -> Tuple[bool, Optional[str]]:
    if channel == "email":
        return send_email(user, [sample_item()])
    if channel == "webhook":
        return send_webhook(setting, user, [sample_item()], test=True)
    return False, "Unbekannter Kanal"


# --- the periodic run ----------------------------------------------------------------


def run(db: Session, now: Optional[datetime] = None) -> dict:
    """One pass over all users. Returns counters for the log."""
    now = now or datetime.now(timezone.utc)
    stats = {"users": 0, "in_app": 0, "email": 0, "webhook": 0, "failed": 0}

    settings = (
        db.query(NotificationSetting)
        .join(User, User.id == NotificationSetting.user_id)
        .filter(User.is_active.is_(True))
        .filter(
            or_(
                NotificationSetting.in_app_enabled.is_(True),
                NotificationSetting.email_enabled.is_(True),
                NotificationSetting.webhook_enabled.is_(True),
            )
        )
        .all()
    )
    for setting in settings:
        user = setting.user
        watches = db.query(WatchedProduct).filter(WatchedProduct.user_id == user.id).all()
        if not watches:
            continue
        stats["users"] += 1

        if setting.in_app_enabled:
            vulns = candidates(db, user, setting, "in_app", watches, now)
            if vulns:
                deliver_in_app(db, user, vulns, watches)
                _record(db, user, vulns, "in_app")
                db.commit()
                stats["in_app"] += len(vulns)

        for channel, enabled, sender in (
            ("email", setting.email_enabled, lambda items: send_email(user, items)),
            ("webhook", setting.webhook_enabled, lambda items: send_webhook(setting, user, items)),
        ):
            if not enabled:
                continue
            vulns = candidates(db, user, setting, channel, watches, now)
            for start in range(0, len(vulns), CHUNK):
                chunk = vulns[start : start + CHUNK]
                ok, error = sender(build_items(chunk, watches))
                if ok:
                    _record(db, user, chunk, channel)
                    setattr(setting, f"last_{channel}_ok_at", now)
                    setattr(setting, f"last_{channel}_error", None)
                    stats[channel] += len(chunk)
                    db.commit()
                else:
                    setattr(setting, f"last_{channel}_error", error)
                    stats["failed"] += 1
                    db.commit()
                    logger.warning("Alert via %s for user %s failed: %s", channel, user.id, error)
                    break  # try again in the next run
    return stats
