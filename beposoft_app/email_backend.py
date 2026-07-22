import ssl

from django.core.mail.backends.smtp import EmailBackend
from django.utils.functional import cached_property


class CustomSMTPEmailBackend(EmailBackend):
    @cached_property
    def ssl_context(self):
        return ssl.create_default_context()