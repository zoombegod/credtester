#!/usr/bin/env python3

import logging

import arrow
import requests
from requests_ntlm import HttpNtlmAuth
from rich.console import Console
from rich.logging import RichHandler
from rich.padding import Padding
from rich.table import Table

from .lib.utils import validator

# Dealing with SSL Warnings
try:
    import requests.packages.urllib3

    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
log = logging.getLogger("rich")

console = Console()


class Ntlm:
    def __init__(self, domain, username, password, remoteName, path):
        """Initialize the NTLM class."""

        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName
        self.path = path

    def run(self):
        """Run the NTLM module."""

        # Set headers for session to look like Mac OS X mail client
        headers = {
            "User-Agent": "AppleExchangeWebServices/814.80.3 accountsd/113",
            "Content-Type": "text/xml; charset=utf-8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        # Validating before attempting to connect
        validator(self.domain, self.username, self.password, self.remoteName)

        try:
            # Attempt to authenticate to target
            ntlm_auth = HttpNtlmAuth(f"{self.domain}\\{self.username}", self.password)

            # Doing some parsing to deal with the path variable
            if self.path:
                if self.path.startswith("/"):
                    url = f"https://{self.remoteName}{self.path}"
                else:
                    url = f"https://{self.remoteName}/{self.path}"
                response = requests.post(
                    url, headers=headers, auth=ntlm_auth, timeout=5, verify=False
                )

            # If no path variable is specified, just use the remoteName
            else:
                url = f"https://{self.remoteName}"
                response = requests.post(
                    url, headers=headers, auth=ntlm_auth, timeout=5, verify=False
                )

        # Deal with arbitrary NTLM exceptions.
        except Exception as e:
            log.error(f"NTLM connection failed with error: {e}")
            return False

        if response.status_code not in {401, 403, 404}:
            return True
        else:
            return False

    def display(self, result):
        """Display the NTLM module."""

        # Get the current time and date
        timestamp = arrow.utcnow().format("YYYY-MM-DD HH:mm:ss")

        # Initialize the table
        ntlm_table = Table(
            show_header=True,
            show_footer=False,
            title=f"Module: NTLM",
            title_justify="left",
            title_style="bold reverse",
        )

        # Define the table headers
        ntlm_table.add_column("Timestamp", justify="left")
        ntlm_table.add_column("Domain")
        ntlm_table.add_column("Username")
        ntlm_table.add_column("Password")
        ntlm_table.add_column("Authentication")

        # Add the row to the table based on results
        if result is True:
            ntlm_table.add_row(
                timestamp,
                self.domain,
                self.username,
                "[REDACTED]",
                "[bold green]Successful[/]",
            )
        else:
            ntlm_table.add_row(
                timestamp,
                self.domain,
                self.username,
                self.password,
                "[bold red]Unsuccessful[/]",
            )

        # Print the table
        console.print(Padding(ntlm_table, (1, 1)))
