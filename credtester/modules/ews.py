#!/usr/bin/env python3


import logging

import arrow
import exchangelib
from exchangelib import DELEGATE, Account, BaseProtocol, Configuration, Credentials
from exchangelib.errors import ErrorNonExistentMailbox, UnauthorizedError
from rich.console import Console
from rich.logging import RichHandler
from rich.padding import Padding
from rich.table import Table

from .lib.utils import validator

logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
log = logging.getLogger("rich")

console = Console()


class Ews:
    def __init__(self, domain, username, password, remoteName):
        """Initialize the ews class."""

        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName

    def run(self):
        """Run the EWS module."""

        # Use this user-agent instead of the default
        BaseProtocol.USERAGENT = "Mozilla/5.0 (X11; Linux x86\_64) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.2 Chrome/51.0.2704.106 Safari/537.36"

        # Validating before attempting to connect
        validator(self.domain, self.username, self.password, self.remoteName)

        # Attempt to authenticate to target
        credentials = Credentials(
            username=f"{self.username}@{self.domain}", password=f"{self.password}"
        )
        config = Configuration(server=f"{self.remoteName}", credentials=credentials)
        try:
            account = Account(
                f"{self.username}@{self.domain}",
                config=config,
                autodiscover=False,
                access_type=DELEGATE,
            )

            # This statement tells us if the user exists and has a mailbox
            # If the user doesn't have a mailbox, we'll get an error
            var = account.inbox.total_count

        # Deal with exchangelib exceptions.
        except ErrorNonExistentMailbox as neb:
            return "DAE"
        except UnauthorizedError as err:
            return False
        except Exception as err:
            log.error(f"Something happened: {err}")
            exit(1)
        else:
            return True

    def display(self, result):
        """Display the ews module."""

        # Get the current time and date
        timestamp = arrow.utcnow().format("YYYY-MM-DD HH:mm:ss")

        # Initialize the table
        ews_table = Table(
            show_header=True,
            show_footer=False,
            title=f"Module: ews",
            title_justify="left",
            title_style="bold reverse",
        )

        # Define the table headers
        ews_table.add_column("Timestamp", justify="left")
        ews_table.add_column("Domain")
        ews_table.add_column("Username")
        ews_table.add_column("Password")
        ews_table.add_column("Authentication")

        # Add the row to the table based on results
        if result is True:
            ews_table.add_row(
                timestamp,
                self.domain,
                self.username,
                "[REDACTED]",
                "[bold green]Successful[/]",
            )
        elif result == "DAE":
            ews_table.add_column("Notes")
            ews_table.add_row(
                timestamp,
                self.domain,
                self.username,
                "[REDACTED]",
                "[bold yellow]Partial Success[/]",
                "No Mailbox",
            )
        else:
            ews_table.add_row(
                timestamp,
                self.domain,
                self.username,
                self.password,
                "[bold red]Unsuccessful[/]",
            )

        # Print the table
        console.print(Padding(ews_table, (1, 1)))
