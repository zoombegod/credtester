#!/usr/bin/env python3
import logging
import sys

import click
from impacket.examples.utils import parse_target
from rich.logging import RichHandler

from .modules.ews import Ews
from .modules.kerberos import Kerberos
from .modules.ldap import Ldap
from .modules.mss import Mss
from .modules.ntlm import Ntlm
from .modules.smb import Smb

logging.basicConfig(
    level="ERROR",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
log = logging.getLogger("rich")


class Credtester:
    def __init__(self, module, domain, username, password, remoteName, path=None):
        """Initialize the credtester class."""

        self.module = module
        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName
        self.path = path

    def run(self):
        """Instantiate the specified module."""
        try:
            self.module = self.module.title()
            mod_name = getattr(sys.modules[__name__], self.module)

            # Dealing with path variable if set for ntlm module
            # Note: This is a bit of a hack, but it works for now
            if self.path:
                module = mod_name(
                    self.domain,
                    self.username,
                    self.password,
                    self.remoteName,
                    self.path,
                )
            else:
                module = mod_name(
                    self.domain, self.username, self.password, self.remoteName
                )

            result = module.run()

        except Exception as err:
            log.error(f"Unable to run module: {err}")
            exit(1)

        return result

    def display(self, result):
        """Display the results of the module."""

        try:
            self.module = self.module.title()
            mod_name = getattr(sys.modules[__name__], self.module)

            # Dealing with path variable if set for ntlm module
            # Note: This is a bit of a hack, but it works for now
            if self.path:
                module = mod_name(
                    self.domain,
                    self.username,
                    self.password,
                    self.remoteName,
                    self.path,
                )
            else:
                module = mod_name(
                    self.domain, self.username, self.password, self.remoteName
                )
            module.display(result)
        except Exception as e:
            log.error(f"Unable to display results: {e}")
            exit(1)


def validate(target):

    # Checking if target specified
    if "@" not in target:
        target = f"{target}@localhost"
        log.info("No target specified, defaulting to localhost")

    # Parsing the input target value
    try:
        domain, username, password, remoteName = parse_target(target)
    except Exception as err:
        exit(1)

    # If domain is not specified, use the local machine
    if domain is None:
        domain = ""
        log.info("No domain specified, using local machine")

    # If password is not specified, prompt for it
    if password == "" and username != "":
        from getpass import getpass

        password = getpass("Password:")

    return domain, username, password, remoteName


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help", "help"])


@click.group()
def cli():
    """Never blur screenshots again!"""
    pass


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("target", required=True, type=click.STRING)
def ldap(target):
    """Test credentials against an LDAP service."""

    module = "ldap"

    # Validate the input target
    domain, username, password, remoteName = validate(target)

    # Instantiate the credtester class
    try:
        credtester = Credtester(module, domain, username, password, remoteName)
    except Exception as err:
        log.error(f"Unable to instantiate credtester: {err}")
        exit(1)

    # Run the module
    result = credtester.run()

    # Display the results
    credtester.display(result)


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("target", required=True, type=click.STRING)
def mss(target):
    """Test credentials against multiple Microsoft services."""

    module = "mss"

    # Validate the input target
    domain, username, password, remoteName = validate(target)

    # Instantiate the credtester class
    try:
        credtester = Credtester(module, domain, username, password, remoteName)
    except Exception as err:
        log.error(f"Unable to instantiate credtester: {err}")
        exit(1)

    # Run the module
    result = credtester.run()

    # Display the results
    credtester.display(result)


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("target", required=True, type=click.STRING)
def smb(target):
    """Test credentials against an SMB service."""

    module = "smb"

    # Validate the input target
    domain, username, password, remoteName = validate(target)

    # Instantiate the credtester class
    try:
        credtester = Credtester(module, domain, username, password, remoteName)

    except Exception as err:
        log.error(f"Unable to instantiate credtester: {err}")
        exit(1)

    # Run the module
    result = credtester.run()

    # Display the results
    credtester.display(result)


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("target", required=True, type=click.STRING)
def ews(target):
    """Test credentials against an EWS service."""

    module = "ews"

    # Validate the input target
    domain, username, password, remoteName = validate(target)

    # Instantiate the credtester class
    try:
        credtester = Credtester(module, domain, username, password, remoteName)

    except Exception as err:
        log.error(f"Unable to instantiate credtester: {err}")
        exit(1)

    # Run the module
    result = credtester.run()

    # Display the results
    credtester.display(result)


@cli.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("target", required=True, type=click.STRING)
@click.option(
    "path",
    "-p",
    "--path",
    help="Path of the NTLM endpoint if required.",
    required=False,
    default="",
)
def ntlm(target, path):
    """Test credentials against an NTLM endpoint."""

    module = "ntlm"

    # Validate the input target
    domain, username, password, remoteName = validate(target)

    # Instantiate the credtester class
    try:
        credtester = Credtester(module, domain, username, password, remoteName, path)

    except Exception as err:
        log.error(f"Unable to instantiate credtester: {err}")
        exit(1)

    # Run the module
    result = credtester.run()

    # Display the results
    credtester.display(result)


if __name__ == "__main__":
    cli()
