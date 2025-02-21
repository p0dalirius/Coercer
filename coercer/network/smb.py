#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : smb.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022


import sys
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError

from coercer.core.Reporter import reporter
from coercer.structures import EscapeCodes

def init_smb_session(args, domain, username, password, address, lmhash, nthash):
    smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
    dialect = smbClient.getDialect()

    dialect_string = "SMBv3.0"
    if dialect == SMB_DIALECT:
        dialect_string = "SMBv1"
    elif dialect == SMB2_DIALECT_002:
        dialect_string = "SMBv2.0"
    elif dialect == SMB2_DIALECT_21:
        dialect_string = "SMBv2.1"
    reporter.print_info("%s dialect used" % dialect_string, verbose=True)

    if args.k is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        reporter.print_info("GUEST Session Granted", verbose=True)
    else:
        reporter.print_info("USER Session Granted", verbose=True)
    return smbClient


def try_login(credentials, target, port=445):
    """Documentation for try_login"""
    # Checking credentials if any
    if not credentials.is_anonymous():
        try:
            smbClient = SMBConnection(
                remoteName=target,
                remoteHost=target,
                sess_port=int(port)
            )
            smbClient.login(
                user=credentials.username,
                password=credentials.password,
                domain=credentials.domain,
                lmhash=credentials.lmhash,
                nthash=credentials.nthash
            )
        except Exception as e:
            reporter.print_error("Could not login as '%s' with these credentials on '%s'." % (credentials.username, target))
            reporter.print("  | Error: %s" % str(e))
            return False
        else:
            return True
    else:
        return True


def list_remote_pipes(target, credentials, share='IPC$', maxdepth=-1):
    """
    Function list_remote_pipes(target, credentials, share='IPC$', maxdepth=-1)
    """
    pipes = []
    try:
        smbClient = SMBConnection(target, target, sess_port=int(445))
        dialect = smbClient.getDialect()
        if credentials.doKerberos is True:
            smbClient.kerberosLogin(credentials.username, credentials.password, credentials.domain, credentials.lmhash, credentials.nthash, credentials.aesKey, credentials.dc_ip)
        else:
            smbClient.login(credentials.username, credentials.password, credentials.domain, credentials.lmhash, credentials.nthash)
        if smbClient.isGuestSession() > 0:
            reporter.print_info("GUEST Session Granted", debug=True)
        else:
            reporter.print_info("USER Session Granted", debug=True)
    except Exception as e:
        reporter.print_error(e, debug=True)
        return pipes

    # Breadth-first search algorithm to recursively find .extension files
    searchdirs = [""]
    depth = 0
    while len(searchdirs) != 0 and ((depth <= maxdepth) or (maxdepth == -1)):
        depth += 1
        next_dirs = []
        for sdir in searchdirs:
            reporter.print_in_progress("Searching in %s " % sdir, debug=True)
            try:
                for sharedfile in smbClient.listPath(share, sdir + "*", password=None):
                    if sharedfile.get_longname() not in [".", ".."]:
                        if sharedfile.is_directory():
                            reporter.print_in_progress("Found directory %s/" % sharedfile.get_longname(), debug=True)
                            next_dirs.append(sdir + sharedfile.get_longname() + "/")
                        else:
                            reporter.print_in_progress("Found file %s" % sharedfile.get_longname(), debug=True)
                            full_path = sdir + sharedfile.get_longname()
                            pipes.append(full_path)
            except SessionError as e:
                reporter.print_error(e, debug=True)
        searchdirs = next_dirs
        reporter.print_in_progress("Next iteration with %d folders." % len(next_dirs), debug=True)
    pipes = sorted(list(set(["\\PIPE\\" + f for f in pipes])), key=lambda x:x.lower())
    return pipes



def can_connect_to_pipe(target, pipe, credentials, targetIp=None):
    """
    Function can_connect_to_pipe(target, pipe, credentials, targetIp=None)
    """
    ncan_target = r'ncacn_np:%s[%s]' % (target, pipe)
    __rpctransport = transport.DCERPCTransportFactory(ncan_target)

    if hasattr(__rpctransport, 'set_credentials'):
        __rpctransport.set_credentials(
            username=credentials.username,
            password=credentials.password,
            domain=credentials.domain,
            lmhash=credentials.lmhash,
            nthash=credentials.nthash
        )

    if credentials.doKerberos:
        __rpctransport.set_kerberos(credentials.doKerberos, kdcHost=credentials.kdcHost)
    if targetIp is not None:
        __rpctransport.setRemoteHost(targetIp)

    dce = __rpctransport.get_dce_rpc()
    # dce.set_auth_type(RPC_C_AUTHN_WINNT)
    # dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    reporter.print_in_progress("Connecting to %s ... " % ncan_target, prefix="         ", end="", verbose=True)
    try:
        dce.connect()
    except Exception as e:
        reporter.print(("fail", EscapeCodes.BOLD_BRIGHT_RED), verbose=True)
        reporter.print_error("Something went wrong, check error status => %s" % str(e), prefix="         ", verbose=True)
        return None
    else:
        reporter.print(("success", EscapeCodes.BOLD_BRIGHT_GREEN), verbose=True)
        return dce


def can_bind_to_interface(target, pipe, credentials, uuid, version, targetIp=None):
    """
    Function can_bind_to_interface(target, pipe, credentials, uuid, version, targetIp=None)
    """
    ncan_target = r'ncacn_np:%s[%s]' % (target, pipe)
    __rpctransport = transport.DCERPCTransportFactory(ncan_target)

    if hasattr(__rpctransport, 'set_credentials'):
        __rpctransport.set_credentials(
            username=credentials.username,
            password=credentials.password,
            domain=credentials.domain,
            lmhash=credentials.lmhash,
            nthash=credentials.nthash
        )

    if credentials.doKerberos:
        __rpctransport.set_kerberos(credentials.doKerberos, kdcHost=credentials.kdcHost)
    if targetIp is not None:
        __rpctransport.setRemoteHost(targetIp)

    dce = __rpctransport.get_dce_rpc()
    # dce.set_auth_type(RPC_C_AUTHN_WINNT)
    # dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    reporter.print_in_progress("Connecting to %s ... " % ncan_target, prefix="         ", end="", verbose=True)
    try:
        dce.connect()
    except Exception as e:
        reporter.print(("fail", EscapeCodes.BOLD_BRIGHT_RED), verbose=True)
        reporter.print_error("Something went wrong, check error status => %s" % str(e), prefix="         ", verbose=True)
        return False

    reporter.print_in_progress("Binding to <uuid='%s', version='%s'> ... " % (uuid, version), prefix="         ", end="", verbose=True)
    try:
        dce.bind(uuidtup_to_bin((uuid, version)))
    except Exception as e:
        reporter.print(("fail", EscapeCodes.BOLD_BRIGHT_RED), verbose=True)
        reporter.print_error("Something went wrong, check error status => %s" % str(e), prefix="         ", verbose=True)
        if "STATUS_PIPE_DISCONNECTED" in str(e):
            # SMB SessionError: STATUS_PIPE_DISCONNECTED()
            return False
        elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
            # SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)
            return False
        elif "STATUS_ACCESS_DENIED" in str(e):
            # SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
            return False
        elif "abstract_syntax_not_supported" in str(e):
            # Bind context 1 rejected: provider_rejection; abstract_syntax_not_supported (this usually means the interface isn't listening on the given endpoint)
            return False
        elif "Unknown DCE RPC packet type received" in str(e):
            # Unknown DCE RPC packet type received: 11
            return False
        elif "Authentication type not recognized" in str(e):
            # DCERPC Runtime Error: code: 0x8 - Authentication type not recognized
            return False
        else:
            return True
    else:
        reporter.print(("success", EscapeCodes.BOLD_BRIGHT_GREEN), verbose=True)
        return True
