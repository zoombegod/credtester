#!/usr/bin/env python3

import logging

import adal
import arrow
from rich.console import Console
from rich.logging import RichHandler
from rich.padding import Padding
from rich.table import Table

from .lib.utils import validator

log = logging.getLogger("adal").setLevel(level=logging.WARNING)

console = Console()


class Mss:
    def __init__(self, domain, username, password, remoteName):
        """Initialize the mss class."""

        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName

    def run(self):
        """Run the mss module."""

        endpoint_table = [
            [1, "AAD Graph API", "https://graph.windows.net"],
            [2, "MS Graph API", "https://graph.microsoft.com"],
            [3, "Azure Managment API", "https://management.azure.com"],
            [4, "Windows Net Management API", "https://management.core.windows.net"],
            [
                5,
                "Cloud Web App Proxy",
                "https://proxy.cloudwebappproxy.net/registerapp",
            ],
            [6, "Office Apps", "https://officeapps.live.com"],
            [7, "Outlook", "https://outlook.office365.com"],
            [8, "Webshell Suite", "https://webshell.suite.office.com"],
            [9, "Sara", "https://api.diagnostics.office.com"],
            [10, "Office Managment", "https://manage.office.com"],
            [11, "MSMA Service", "https://msmamservice.api.application"],
            [12, "Space API", "https://api.spaces.skype.com"],
            [13, "Data Catalog", "https://datacatalog.azure.com"],
            [14, "Database", "https://database.windows.net"],
            [15, "Azure Key Vault", "https://vault.azure.net"],
            [16, "Onenote", "https://onenote.com"],
            [17, "O365 Yammer", "https://api.yammer.com"],
            [18, "Skype For Business", "https://api.skypeforbusiness.com"],
            [19, "O365 Exchange", "https://outlook-sdf.office.com"],
        ]

        # Attempt to authenticate to target
        context = adal.AuthenticationContext(
            "https://login.microsoftonline.com/common",
            api_version=None,
            proxies=None,
            verify_ssl=True,
        )

        # Validating before attempting to connect
        validator(self.domain, self.username, self.password, self.remoteName)

        for endpoint in endpoint_table:
            for i in range(0, len(endpoint_table)):
                try:
                    token = context.acquire_token_with_username_password(
                        endpoint[2],
                        f"{self.username}@{self.domain}",
                        self.password,
                        "1b730954-1685-4b74-9bfd-dac224a7b894",
                    )
                    if token:
                        result = "[bold green]Successful[/]"
                        endpoint_table[i].extend([True, result])
                except adal.adal_error.AdalError as e:
                    error_code = e.error_response["error_codes"][0]
                    if error_code == 50076:
                        result = "[bold yellow]Partial Success: MFA Required[/]"
                        endpoint_table[i].extend([False, result])
                    elif error_code == 50158:
                        result = (
                            "[bold yellow]Partial Success: Conditional Access Policy[/]"
                        )
                        endpoint_table[i].extend([False, result])
                    elif error_code == 50053:
                        result = "[bold yellow]Partial Success: Account Locked[/]"
                        endpoint_table[i].extend([False, result])
                    elif error_code == 50057:
                        result = "[bold yellow]Partial Success: Account Disabled[/]"
                        endpoint_table[i].extend([False, result])
                    elif error_code == 50055:
                        result = "[bold yellow]Partial Success: Password Expired[/]"
                        endpoint_table[i].extend([False, result])
                    else:
                        result = "[bold red]Unsuccessful[/]"
                        endpoint_table[i].extend([False, result])

            return endpoint_table

    def display(self, result):
        """Display the mss module."""

        # Get the current time and date
        timestamp = arrow.utcnow().format("YYYY-MM-DD HH:mm:ss")

        # Initialize the table
        mss_table = Table(
            show_header=True,
            show_footer=False,
            title=f"Module: mss",
            title_justify="left",
            title_style="bold reverse",
        )

        # Define the table headers
        mss_table.add_column("Timestamp", justify="left")
        mss_table.add_column("Endpoint")
        mss_table.add_column("Domain")
        mss_table.add_column("Username")
        mss_table.add_column("Password")
        mss_table.add_column("Authentication")

        # Add the row to the table based on results
        for r in range(0, len(result)):
            if "Partial" in result[r][4]:
                self.password = "[REDACTED]"
                continue

        # Add the row to the table based on results
        if result[0][3] == True:
            self.password = "[REDACTED]"

        for r in result:
            mss_table.add_row(
                timestamp,
                r[1],
                self.domain,
                self.username,
                self.password,
                r[4],
            )

        # Print the table
        console.print(Padding(mss_table, (1, 1)))
