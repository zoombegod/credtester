#!/usr/bin/env python3

import logging

import arrow
from impacket.smbconnection import (
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB_DIALECT,
    SMBConnection,
)
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


class Smb:
    def __init__(self, domain, username, password, remoteName):
        """Initialize the template class."""

        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName

    def run(self):
        """Run the SMB module."""

        # Validating before attempting to connect
        validator(self.domain, self.username, self.password, self.remoteName)

        # Attempt to authenticate to target
        try:
            smbConnection = SMBConnection(self.remoteName, self.remoteName)
            smbConnection.login(self.username, self.password, self.domain)
            return True

        # Deal with arbitrary SMB exceptions.
        except Exception as e:
            log.error(f"SMB connection failed with error: {e}")
            return False

    def display(self, result):
        """Display the template module."""

        # Get the current time and date
        timestamp = arrow.utcnow().format("YYYY-MM-DD HH:mm:ss")

        # Making sure we add a value to domain if it is empty
        if self.domain == "":
            self.domain = "N/A"

        # Initialize the table
        smb_table = Table(
            show_header=True,
            show_footer=False,
            title=f"Module: SMB",
            title_justify="left",
            title_style="bold reverse",
        )

        # Define the table headers
        smb_table.add_column("Timestamp", justify="left")
        smb_table.add_column("Domain")
        smb_table.add_column("Username")
        smb_table.add_column("Password")
        smb_table.add_column("Authentication")

        # Add the row to the table based on results
        if result is True:
            smb_table.add_row(
                timestamp,
                self.domain,
                self.username,
                "[REDACTED]",
                "[bold green]Successful[/]",
            )
        else:
            smb_table.add_row(
                timestamp,
                self.domain,
                self.username,
                self.password,
                "[bold red]Unsuccessful[/]",
            )

        # Print the table
        console.print(Padding(smb_table, (1, 1)))
