<div align="center">

# credtester 

![](https://img.shields.io/github/stars/Summertime2022/credtester)
![](https://img.shields.io/pypi/dd/credtester)
![](https://img.shields.io/pypi/v/credtester)

Credtester is a command-line tool that allows you to test the validity of username and password for multiple Microsoft services.
<br>

[Installation](#installation) •
[Getting started](#getting-started) •
[Usage](#usage) •
[Coming Soon](#coming-soon)

</div><br>


Credtester is built for use in offensive security reporting. The tool has the following features:

* Parse input credentials using an impacket like format. 
* Pretty table output for screenshots in client reports in an easy to understand format.
* Obscures plaintext passwords if authentication is successful. This skips the step everyone takes to blur output.
* Supports several protocols and endpoints for external and internal assessments. 

Example output from the tool and its usage is shown below:

![](https://github.com/Summertime2022/credtester/img/successful_auth_ews.gif)
![](https://github.com/Summertime2022/credtester/img/failed_auth.gif)

**If authentication is successful, the plaintext password used will be replaced with `[REDACTED]`. If authentication fails, the entered plaintext password will be displayed**

</div>
<br>

## Installation
Credtester supports all major operating systems and can be installed for the PyPi using the following command:

```
pip3 install credtester
```

Alternatively, you can install the tool from source and use it with Poetry. This is ideal for development:

```
git clone https://github.com/Summertime2022/credtester.git
cd credtester
poetry shell && poetry install
```

<br>

## Getting started

Credtester supports the following protocols:

* LDAP/LDAPS
* SMB
* Exchange web services for both Exchange and O365 (EWS)
* Several Microsoft cloud authentication endpoints
* NTLM web directories

Once installed all modules will be executed in a format similar to what is shown below:

```
credtester smb acme.com/user:password@dc1.acme.com
```

If you don't want to specify the password in your command, simply execute something similar to the following:

```
credtester ldap acme.com/user@dc1.acme.com
```

After hitting enter, you will be prompted to enter a password. 

<br>

## Usage

```
ct --help
Usage: ct [OPTIONS] COMMAND [ARGS]...

  Never blur screenshots again!

Options:
  --help  Show this message and exit.

Commands:
  ews   Test credentials against an EWS service.
  ldap  Test credentials against an LDAP service.
  mss   Test credentials against multiple Microsoft services.
  ntlm  Test credentials against an NTLM endpoint.
  smb   Test credentials against an SMB service.
```

Some notes on each module are below:

### EWS

The EWS module can be used to test for successful authentication while targeting Microsoft Exchange and Office365. If testing Exchange, the table displayed will be different dependent on if the user has a mailbox:

![](https://github.com/Summertime2022/credtester/img/partial_success_ews.gif)

If you are targeting O365, note that you will need to specify the target as:

* outlook.office365.com

### LDAP

The LDAP module can be used to test credentials while targeting Microsoft directory services. If LDAP (plaintext) authentication is unsuccessful due to connection restrictions, the tool will fall back and attempt to authenticate via LDAPS (encrypted)

### MSS
This module is based on the tool [msspray](https://github.com/SecurityRiskAdvisors/msspray). When using this module, the credentials entered will be attempted against a sizeable list of Microsoft cloud authentication endpoints. 
<br>

This module can and will account for authentication errors such as:

* MFA requirements
* Expired passwords
* Disabled accounts

If any of the attempts made to authenticate are even partially successful, the password will be obscured from output. 

### NTLM

This module allows you to specify a specific directory on a webserver and authenticate using NTLM over HTTP. The help menu for this module is shown below:

```
Usage: ct ntlm [OPTIONS] TARGET

  Test credentials against an NTLM endpoint.

Options:
  -p, --path TEXT  Path of the NTLM endpoint if required.
  -h, --help       Show this message and exit.
```

Note the `--path` option shown above. If a path is not specified, the root of the webserver is used.

### SMB
This module simply allows you to test credentials against an SMB service. Nothing else to note here. 


<br>

## Coming Soon
Some planned features coming in the next release:

* Support for hashes instead of passwords
* SOCKS proxy support for use with implants/C2 frameworks
* Option to display password strength based on tester specified policy
* Option to always hide the input password from table output
* Ability to check if the user is an administrator for the targeted protocol.
* Better template for creating new modules
* A fixed Kerberos module

## Thanks

* My great team for helping me come up with this idea
* The tool [msspray](https://github.com/SecurityRiskAdvisors/msspray) for the included MSS module
* [Crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) for authentication code (LDAP/SMB)
* This [blog](https://www.sprocketsecurity.com/blog/how-to-bypass-mfa-all-day) from Sprocket Security on NTLM over HTTP authentication.
