import smtplib
import ssl

from django.core.mail.backends.smtp import EmailBackend
from django.utils.functional import cached_property


class CustomSMTPEmailBackend(EmailBackend):

    @cached_property
    def ssl_context(self):
        return ssl.create_default_context()

    def open(self):
        if self.connection:
            return False

        connection_params = {
            "local_hostname": "psage.in",
            "timeout": self.timeout,
        }

        if self.use_ssl:
            connection_params["context"] = self.ssl_context

        try:
            self.connection = self.connection_class(
                self.host,
                self.port,
                **connection_params,
            )

            if not self.use_ssl and self.use_tls:
                self.connection.starttls(context=self.ssl_context)

            if self.username and self.password:
                self.connection.login(
                    self.username,
                    self.password,
                )

            return True

        except OSError:
            if not self.fail_silently:
                raise