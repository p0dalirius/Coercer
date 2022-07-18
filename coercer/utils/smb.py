#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : smbutils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import sys
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin


def connect_to_pipe(pipe, username, password, domain, lmhash, nthash, target, dcHost, doKerberos=False, targetIp=None, verbose=False):
    ncan_target = r'ncacn_np:%s[%s]' % (target, pipe)
    __rpctransport = transport.DCERPCTransportFactory(ncan_target)

    if hasattr(__rpctransport, 'set_credentials'):
        __rpctransport.set_credentials(
            username=username,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash
        )

    if doKerberos:
        __rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
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


def can_bind_to_protocol(dce, uuid, version, verbose=False):
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


def get_available_pipes_and_protocols(options, target, lmhash, nthash, all_pipes, available_protocols):
    for pipe in all_pipes:
        dce = connect_to_pipe(pipe=pipe, username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=target, doKerberos=options.kerberos, dcHost=options.dc_ip, verbose=options.verbose)
        if dce is not None:
            print("   [>] Pipe '%s' is \x1b[1;92maccessible\x1b[0m!" % pipe)
            for protocol in available_protocols:
                if pipe in protocol.available_pipes:
                    dce = connect_to_pipe(pipe=pipe, username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, doKerberos=options.kerberos, dcHost=options.dc_ip, targetIp=options.target_ip, verbose=options.verbose)
                    if dce is not None:
                        if can_bind_to_protocol(dce, protocol.uuid, protocol.version, verbose=options.verbose):
                            for method, opnum, comment in protocol.list_coerce_methods():
                                if comment is not None:
                                    print("      [>] %s (uuid=%s, version=%s) %s (opnum %d) | %s" % (protocol.shortname, protocol.uuid, protocol.version, method, opnum, comment))
                                else:
                                    print("      [>] %s (uuid=%s, version=%s) %s (opnum %d) " % (protocol.shortname, protocol.uuid, protocol.version, method, opnum))
        else:
            if options.verbose or options.analyze:
                print("   [>] Pipe '%s' is \x1b[1;91mnot accessible\x1b[0m!" % pipe)
