import logging
import mimetypes

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.html import escape
from django.utils.text import Truncator


logger = logging.getLogger(__name__)


def parse_boolean(value):
    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_valid_email(user):
    email = (
        getattr(user, "email", "")
        or ""
    ).strip().lower()

    if not email:
        return None

    try:
        validate_email(email)
    except ValidationError:
        return None

    return email


def remove_duplicate_email_groups(
    to_emails,
    cc_emails,
    bcc_emails,
):
    """
    Priority:
    To > CC > BCC

    If an address is already in To, remove it from CC and BCC.
    If an address is already in CC, remove it from BCC.
    """

    unique_to = []
    unique_cc = []
    unique_bcc = []

    seen = set()

    for email in to_emails:
        normalized = email.strip().lower()

        if normalized and normalized not in seen:
            unique_to.append(normalized)
            seen.add(normalized)

    for email in cc_emails:
        normalized = email.strip().lower()

        if normalized and normalized not in seen:
            unique_cc.append(normalized)
            seen.add(normalized)

    for email in bcc_emails:
        normalized = email.strip().lower()

        if normalized and normalized not in seen:
            unique_bcc.append(normalized)
            seen.add(normalized)

    return unique_to, unique_cc, unique_bcc


def users_to_email_list(users):
    emails = []

    for user in users:
        email = get_valid_email(user)

        if email:
            emails.append(email)

    return emails


def build_html_message(
    sender_name,
    sender_email,
    message,
):
    safe_sender_name = escape(
        sender_name or "PSAGE User"
    )

    safe_sender_email = escape(
        sender_email or ""
    )

    safe_message = escape(
        message or ""
    ).replace("\n", "<br>")

    return f"""
    <div style="
        font-family: Arial, sans-serif;
        font-size: 14px;
        line-height: 1.6;
        color: #222;
    ">
        <div>{safe_message}</div>

        <hr style="
            margin-top: 24px;
            border: 0;
            border-top: 1px solid #ddd;
        ">

        <div style="
            color: #666;
            font-size: 12px;
        ">
            Sent through the PSAGE internal mail system.<br>
            Sender: {safe_sender_name}
            &lt;{safe_sender_email}&gt;
        </div>
    </div>
    """



def attach_internal_mail_files(
    email_message,
    attachments,
):
    for attachment in attachments:
        document = attachment.document

        if not document or not document.name:
            continue

        try:
            document.open("rb")
            content = document.read()

        except FileNotFoundError:
            logger.warning(
                "Skipping missing internal-mail attachment. "
                "Attachment ID=%s, file=%s",
                attachment.pk,
                document.name,
            )
            continue

        except Exception:
            logger.exception(
                "Unable to attach internal-mail file. "
                "Attachment ID=%s, file=%s",
                attachment.pk,
                document.name,
            )
            continue

        finally:
            try:
                document.close()
            except Exception:
                pass

        filename = document.name.rsplit("/", 1)[-1]

        content_type, _ = mimetypes.guess_type(filename)

        email_message.attach(
            filename,
            content,
            content_type or "application/octet-stream",
        )


def send_internal_mail_externally(
    internal_mail,
    to_users,
    cc_users,
    bcc_users,
):
    """
    Authenticate using EMAIL_HOST_USER, but use the logged-in
    user's profile email as the From address.

    This requires the SMTP server to permit EMAIL_HOST_USER
    to send as other authorised @psage.in addresses.
    """

    sender = internal_mail.sender

    sender_email = get_valid_email(sender)

    if not sender_email:
        raise ValueError(
            "The sender profile does not contain "
            "a valid email address."
        )

    allowed_domain = "@psage.in"

    if not sender_email.endswith(
        allowed_domain
    ):
        raise ValueError(
            "External sender must use a valid "
            "@psage.in profile email address."
        )

    to_emails = users_to_email_list(
        to_users
    )

    cc_emails = users_to_email_list(
        cc_users
    )

    bcc_emails = users_to_email_list(
        bcc_users
    )

    (
        to_emails,
        cc_emails,
        bcc_emails,
    ) = remove_duplicate_email_groups(
        to_emails=to_emails,
        cc_emails=cc_emails,
        bcc_emails=bcc_emails,
    )

    all_recipient_count = (
        len(to_emails)
        + len(cc_emails)
        + len(bcc_emails)
    )

    if all_recipient_count == 0:
        raise ValueError(
            "None of the selected recipients "
            "has a valid email address."
        )

    sender_name = (
        getattr(sender, "name", "")
        or sender_email.split("@")[0]
    ).strip()

    # from_email = (
    #     f"{sender_name} <{sender_email}>"
    # )
    from_email = f"{sender_name} via PSAGE <{settings.EMAIL_HOST_USER}>"

    plain_message = (
        internal_mail.message
        or ""
    ).strip()

    if not plain_message:
        plain_message = (
            "Please see the attached document."
        )

    from django.core.mail import get_connection

    connection = get_connection(
        backend=settings.EMAIL_BACKEND,
        fail_silently=False,
    )

    email_message = EmailMultiAlternatives(
        subject=internal_mail.subject,
        body=plain_message,
        from_email=from_email,
        to=to_emails,
        cc=cc_emails,
        bcc=bcc_emails,
        headers={
            "Reply-To": sender_email,
            "X-Internal-Mail-ID": str(internal_mail.pk),
        },
        connection=connection,
    )

    html_message = build_html_message(
        sender_name=sender_name,
        sender_email=sender_email,
        message=plain_message,
    )

    email_message.attach_alternative(
        html_message,
        "text/html",
    )

    attach_internal_mail_files(
        email_message=email_message,
        attachments=internal_mail.attachments.all(),
    )

    sent_count = email_message.send(
        fail_silently=False,
    )

    if sent_count != 1:
        raise RuntimeError(
            "SMTP server did not confirm "
            "the email delivery request."
        )

    internal_mail.external_email_status = "sent"
    internal_mail.external_sender_email = sender_email
    internal_mail.external_sent_at = timezone.now()
    internal_mail.external_email_error = None
    internal_mail.external_recipient_count = (
        all_recipient_count
    )

    internal_mail.save(
        update_fields=[
            "external_email_status",
            "external_sender_email",
            "external_sent_at",
            "external_email_error",
            "external_recipient_count",
        ]
    )

    return {
        "status": "sent",
        "sender": sender_email,
        "to_count": len(to_emails),
        "cc_count": len(cc_emails),
        "bcc_count": len(bcc_emails),
        "recipient_count": all_recipient_count,
    }


def process_external_internal_mail(
    internal_mail_id,
    to_user_ids,
    cc_user_ids,
    bcc_user_ids,
):
    """
    Called after the internal-mail database transaction commits.
    """

    from beposoft_app.models import (
        InternalMail,
        User,
    )

    try:
        internal_mail = (
            InternalMail.objects
            .select_related("sender")
            .prefetch_related("attachments")
            .get(pk=internal_mail_id)
        )

        to_users = list(
            User.objects.filter(
                id__in=to_user_ids
            )
        )

        cc_users = list(
            User.objects.filter(
                id__in=cc_user_ids
            )
        )

        bcc_users = list(
            User.objects.filter(
                id__in=bcc_user_ids
            )
        )

        return send_internal_mail_externally(
            internal_mail=internal_mail,
            to_users=to_users,
            cc_users=cc_users,
            bcc_users=bcc_users,
        )

    except Exception as exc:
        logger.exception(
            "External internal-mail delivery failed "
            "for mail ID %s",
            internal_mail_id,
        )

        InternalMail.objects.filter(
            pk=internal_mail_id
        ).update(
            external_email_status="failed",
            external_email_error=Truncator(
                str(exc)
            ).chars(2000),
        )

        return {
            "status": "failed",
            "error": str(exc),
        }