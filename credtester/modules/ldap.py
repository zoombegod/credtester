#!/usr/bin/env python3

import logging

import arrow
from impacket.ldap import ldap as ldap_impacket
from impacket.ntlm import compute_lmhash, compute_nthash
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
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


class Ldap:
    def __init__(self, domain, username, password, remoteName):
        """Initialize the ldap class."""

        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName

    def run(self):
        """Run the LDAP module."""

        # Setting these as none until implemented
        lmhash = ""
        nthash = ""

        # Create the baseDN
        baseDN = ""
        domainParts = self.domain.split(".")
        for i in domainParts:
            baseDN += f"dc={i},"

        # Remove last ','
        baseDN = baseDN[:-1]

        # Validating before attempting to connect
        validator(self.domain, self.username, self.password, self.remoteName)

        try:
            ldapConnection = ldap_impacket.LDAPConnection(
                "ldap://%s" % self.domain, baseDN, self.domain
            )

            ldapConnection.login(
                self.username, self.password, self.domain, lmhash, nthash
            )
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:

                # We need to try SSL
                try:
                    ldapConnection = ldap_impacket.LDAPConnection(
                        "ldaps://%s" % self.domain, baseDN, self.domain
                    )
                    ldapConnection.login(
                        self.username, self.password, self.domain, lmhash, nthash
                    )
                    return True
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    return False

    def display(self, result):
        """Display the LDAP module."""

        # Get the current time and date
        timestamp = arrow.utcnow().format("YYYY-MM-DD HH:mm:ss")

        # Initialize the table
        ldap_table = Table(
            show_header=True,
            show_footer=False,
            title=f"Module: LDAP",
            title_justify="left",
            title_style="bold reverse",
        )

        # Define the table headers
        ldap_table.add_column("Timestamp", justify="left")
        ldap_table.add_column("Domain")
        ldap_table.add_column("Username")
        ldap_table.add_column("Password")
        ldap_table.add_column("Authentication")

        # Add the row to the table based on results
        if result is True:
            ldap_table.add_row(
                timestamp,
                self.domain,
                self.username,
                "[REDACTED]",
                "[bold green]Successful[/]",
            )
        else:
            ldap_table.add_row(
                timestamp,
                self.domain,
                self.username,
                self.password,
                "[bold red]Unsuccessful[/]",
            )

        # Print the table
        console.print(Padding(ldap_table, (1, 1)))
