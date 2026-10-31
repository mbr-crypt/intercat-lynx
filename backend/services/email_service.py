"""
Email service for sending verification codes.
For development: Logs codes to console.
For production: Use SMTP or email service (SendGrid, AWS SES, etc.)
"""

import logging
import os

logger = logging.getLogger(__name__)


def _cfg(key: str, env_name: str, default=None):
    """Database setting (set by the setup assistant) > environment > default."""
    from .settings_service import runtime

    return runtime(key, env_name, default)


class EmailService:
    """Email service for sending verification codes and emails."""

    def __init__(self):
        self.environment = os.getenv("ENVIRONMENT", "development")

    @property
    def smtp_enabled(self) -> bool:
        return str(_cfg("smtp.enabled", "SMTP_ENABLED", "false")).lower() == "true"

    def _smtp_send(self, msg, to_email: str) -> None:
        """
        Deliver a prepared message. Transport security is configurable:
        ``starttls`` (port 587, default), ``ssl`` (port 465) or ``none``.
        """
        import smtplib
        import ssl

        host = _cfg("smtp.host", "SMTP_HOST", "localhost")
        port = int(_cfg("smtp.port", "SMTP_PORT", "587"))
        security = str(_cfg("smtp.security", "SMTP_SECURITY", "starttls")).lower()
        username = _cfg("smtp.username", "SMTP_USERNAME")
        password = _cfg("smtp.password", "SMTP_PASSWORD")
        context = ssl.create_default_context()

        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=20, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            server.send_message(msg)

    def _sender(self):
        username = _cfg("smtp.username", "SMTP_USERNAME")
        from_email = _cfg("smtp.from_email", "SMTP_FROM_EMAIL", username)
        from_name = _cfg("smtp.from_name", "SMTP_FROM_NAME", "InterCat Lynx")
        return from_name, from_email

    async def send_email(
        self, to_email: str, subject: str, html_content: str, text_content: str
    ) -> bool:
        """
        Send email with HTML and text content.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email body
            text_content: Plain text email body

        Returns:
            True if sent successfully
        """
        if self.environment == "development" or not self.smtp_enabled:
            # Development mode: Log to console
            logger.info("=" * 60)
            logger.info(f"EMAIL")
            logger.info(f"To: {to_email}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Text Content:\n{text_content}")
            logger.info("=" * 60)
            print(f"\nEMAIL to {to_email}: {subject}\n{text_content}\n")
            return True
        else:
            # Production mode: Send actual email
            return await self._send_smtp_email_html(
                to_email, subject, html_content, text_content
            )

    async def send_verification_code(
        self, email: str, code: str, verification_type: str = "registration"
    ) -> bool:
        """
        Send verification code to email.

        Args:
            email: Recipient email address
            code: 6-digit verification code
            verification_type: 'registration' or 'email_change'

        Returns:
            True if sent successfully
        """
        subject = self._get_subject(verification_type)
        message = self._get_message(code, verification_type)

        if self.environment == "development" or not self.smtp_enabled:
            # Development mode: Log to console
            logger.info("=" * 60)
            logger.info(f"EMAIL VERIFICATION CODE")
            logger.info(f"To: {email}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Code: {code}")
            logger.info(f"Type: {verification_type}")
            logger.info(f"Message:\n{message}")
            logger.info("=" * 60)
            print(f"\nVERIFICATION CODE for {email}: {code}\n")
            return True
        else:
            # Production mode: Send actual email
            return await self._send_smtp_email(email, subject, message)

    def _get_subject(self, verification_type: str) -> str:
        """Get email subject based on verification type."""
        if verification_type == "registration":
            return "InterCat Lynx - Verify Your Email Address"
        elif verification_type == "email_change":
            return "InterCat Lynx - Confirm Email Change"
        return "InterCat Lynx - Verification Code"

    def _get_message(self, code: str, verification_type: str) -> str:
        """Get email message based on verification type."""
        if verification_type == "registration":
            return f"""
Welcome to InterCat Lynx!

Your verification code is: {code}

This code will expire in 15 minutes.

If you didn't create an account, please ignore this email.

Best regards,
InterCat Lynx Team
"""
        elif verification_type == "email_change":
            return f"""
Email Change Request

Your verification code is: {code}

This code will expire in 15 minutes.

If you didn't request this change, please secure your account immediately.

Best regards,
InterCat Lynx Team
"""
        return f"Your verification code is: {code}"

    async def _send_smtp_email(self, email: str, subject: str, message: str) -> bool:
        """Send a plain text email via SMTP."""
        try:
            from email.mime.text import MIMEText

            from_name, from_email = self._sender()
            if not from_email:
                logger.error("SMTP sender address not configured")
                return False
            msg = MIMEText(message, "plain", "utf-8")
            msg["From"] = f"{from_name} <{from_email}>"
            msg["To"] = email
            msg["Subject"] = subject
            self._smtp_send(msg, email)
            logger.info("Email sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {type(e).__name__}: {e}")
            return False

    async def _send_smtp_email_html(
        self, email: str, subject: str, html_content: str, text_content: str
    ) -> bool:
        """Send an HTML email (with plain text alternative) via SMTP."""
        try:
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            from_name, from_email = self._sender()
            if not from_email:
                logger.error("SMTP sender address not configured")
                return False
            msg = MIMEMultipart("alternative")
            msg["From"] = f"{from_name} <{from_email}>"
            msg["To"] = email
            msg["Subject"] = subject
            msg.attach(MIMEText(text_content, "plain", "utf-8"))
            msg.attach(MIMEText(html_content, "html", "utf-8"))
            self._smtp_send(msg, email)
            logger.info("HTML email sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send HTML email: {type(e).__name__}: {e}")
            return False

    async def send_test_email(self, to_email: str) -> tuple:
        """Always really send (used by the setup assistant). Returns (ok, error)."""
        try:
            from email.mime.text import MIMEText

            from_name, from_email = self._sender()
            if not from_email:
                return False, "Absenderadresse fehlt"
            msg = MIMEText(
                "Dies ist eine Testnachricht von InterCat Lynx. "
                "Der E-Mail-Versand funktioniert.",
                "plain",
                "utf-8",
            )
            msg["From"] = f"{from_name} <{from_email}>"
            msg["To"] = to_email
            msg["Subject"] = "InterCat Lynx: Test des E-Mail-Versands"
            self._smtp_send(msg, to_email)
            return True, None
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"


# Singleton instance
email_service = EmailService()
