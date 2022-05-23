#!/usr/bin/env python3

import logging
import socket
from binascii import unhexlify

import arrow
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from rich.console import Console
from rich.logging import RichHandler
from rich.padding import Padding
from rich.table import Table

logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
log = logging.getLogger("rich")

console = Console()


class Kerberos:
    def __init__(self, domain, username, password, remoteName):
        """Initialize the kerberos class."""

        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName

    def run(self):
        """Run the kerberos module."""

        # Setting these as none until implemented
        lmhash = ""
        nthash = ""
        aeskey = None
        kdcHost = None

        # Create the baseDN
        baseDN = ""
        domainParts = self.domain.split(".")
        for i in domainParts:
            baseDN += f"dc={i},"

        # Remove last ','
        baseDN = baseDN[:-1]

        try:

            userName = Principal(
                self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )

            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName, self.password, self.domain, lmhash, nthash, aeskey, kdcHost
            )

            return True
        except Exception as e:
            print(e)
            return False

    def display(self, result):
        """Display the template module."""

        # Get the current time and date
        timestamp = arrow.utcnow().format("YYYY-MM-DD HH:mm:ss")

        # Initialize the table
        kerberos_table = Table(
            show_header=True,
            show_footer=False,
            title=f"Module: Kerberos",
            title_justify="left",
            title_style="bold reverse",
        )

        # Define the table headers
        kerberos_table.add_column("Timestamp", justify="left")
        kerberos_table.add_column("Domain")
        kerberos_table.add_column("Username")
        kerberos_table.add_column("Password")
        kerberos_table.add_column("Authentication")

        # Add the row to the table based on results
        if result is True:
            kerberos_table.add_row(
                timestamp,
                self.domain,
                self.username,
                "[REDACTED]",
                "[bold green]Successful[/]",
            )
        else:
            kerberos_table.add_row(
                timestamp,
                self.domain,
                self.username,
                self.password,
                "[bold red]Unsuccessful[/]",
            )

        # Print the table
        console.print(Padding(kerberos_table, (1, 1)))
