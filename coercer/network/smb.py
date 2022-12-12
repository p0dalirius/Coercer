#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : smb.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022


import sys
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError


def init_smb_session(args, domain, username, password, address, lmhash, nthash, verbose=False):
    smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        if verbose:
            print("[debug] SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        if verbose:
            print("[debug] SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        if verbose:
            print("[debug] SMBv2.1 dialect used")
    else:
        if verbose:
            print("[debug] SMBv3.0 dialect used")
    if args.k is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        if verbose:
            print("[debug] GUEST Session Granted")
    else:
        if verbose:
            print("[debug] USER Session Granted")
    return smbClient


def try_login(credentials, target, port=445, verbose=False):
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
            print("[!] Could not login as '%s' with these credentials on '%s'." % (credentials.username, target))
            print("  | Error: %s" % str(e))
            return False
        else:
            return True
    else:
        return True


def list_remote_pipes(target, credentials, share='IPC$', maxdepth=-1, debug=False):
    """
    Function list_remote_pipes(target, credentials, share='IPC$', maxdepth=-1, debug=False)
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
            if debug:
                print("[>] GUEST Session Granted")
        else:
            if debug:
                print("[>] USER Session Granted")
    except Exception as e:
        if debug:
            print(e)
        return pipes

    # Breadth-first search algorithm to recursively find .extension files
    searchdirs = [""]
    depth = 0
    while len(searchdirs) != 0 and ((depth <= maxdepth) or (maxdepth == -1)):
        depth += 1
        next_dirs = []
        for sdir in searchdirs:
            if debug:
                print("[>] Searching in %s " % sdir)
            try:
                for sharedfile in smbClient.listPath(share, sdir + "*", password=None):
                    if sharedfile.get_longname() not in [".", ".."]:
                        if sharedfile.is_directory():
                            if debug:
                                print("[>] Found directory %s/" % sharedfile.get_longname())
                            next_dirs.append(sdir + sharedfile.get_longname() + "/")
                        else:
                            if debug:
                                print("[>] Found file %s" % sharedfile.get_longname())
                            full_path = sdir + sharedfile.get_longname()
                            pipes.append(full_path)
            except SessionError as e:
                if debug:
                    print("[error] %s " % e)
        searchdirs = next_dirs
        if debug:
            print("[>] Next iteration with %d folders." % len(next_dirs))
    pipes = sorted(list(set(["\\PIPE\\" + f for f in pipes])), key=lambda x:x.lower())
    return pipes



def can_connect_to_pipe(target, pipe, credentials, targetIp=None, verbose=False):
    """
    Function can_connect_to_pipe(target, pipe, credentials, targetIp=None, verbose=False)
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

    if verbose:
        print("         [>] Connecting to %s ... " % ncan_target, end="")
    sys.stdout.flush()
    try:
        dce.connect()
    except Exception as e:
        if verbose:
            print("\x1b[1;91mfail\x1b[0m")
            print("      [!] Something went wrong, check error status => %s" % str(e))
        return None
    else:
        if verbose:
            print("\x1b[1;92msuccess\x1b[0m")
        return dce


def can_bind_to_interface(target, pipe, credentials, uuid, version, targetIp=None, verbose=False):
    """
    Function can_bind_to_interface(target, pipe, credentials, uuid, version, targetIp=None, verbose=False)
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

    if verbose:
        print("         [>] Connecting to %s ... " % ncan_target, end="")
    sys.stdout.flush()
    try:
        dce.connect()
    except Exception as e:
        if verbose:
            print("\x1b[1;91mfail\x1b[0m")
            print("      [!] Something went wrong, check error status => %s" % str(e))
        return False

    if verbose:
        print("         [>] Binding to <uuid='%s', version='%s'> ... " % (uuid, version), end="")
    sys.stdout.flush()
    try:
        dce.bind(uuidtup_to_bin((uuid, version)))
    except Exception as e:
        if verbose:
            print("\x1b[1;91mfail\x1b[0m")
            print("         [!] Something went wrong, check error status => %s" % str(e))
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
        if verbose:
            print("\x1b[1;92msuccess\x1b[0m")
        return True
