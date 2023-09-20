#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : rpc.py
# Author             : soier (@s0i37)
# Date created       : 13 Jul 2023


import sys
import socket
from impacket.dcerpc.v5 import transport, epm
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


def portmap_discover(target, port=135):
    stringBinding = r'ncacn_ip_tcp:%s[%d]' % (target, port)
    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    entries = epm.hept_lookup(None, dce=dce)
    endpoints = {}
    ports = set()
    for entry in entries:
        binding = epm.PrintStringBinding(entry['tower']['Floors'])
        uuid = str(entry['tower']['Floors'][0])
        _transport,dst = binding.split(":")
        try: endpoints[_transport]
        except: endpoints[_transport] = {}
        
        try: endpoints[_transport][uuid]
        except: endpoints[_transport][uuid] = set()
        if _transport == "ncacn_np":
            dst = dst.split("[")[1].split("]")[0]
        elif _transport == "ncacn_ip_tcp":
            dst = int(dst.split("[")[1].split("]")[0])
            ports.add(dst)
        elif _transport == "ncalrpc":
            dst = dst[1:-1]
        endpoints[_transport][uuid].add(dst)
    print("[*] DCERPC portmapper discovered ports: %s" % ",".join(list(map(str, ports))))
    return endpoints


def is_port_open(target, port, verbose=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if verbose:
        print("         [>] Connecting to %s:%d ... " % (target, port), end="")
    sys.stdout.flush()
    try:
        s.connect((socket.gethostbyname(target), int(port)))
    except Exception as e:
        if verbose:
            print("\x1b[1;91mfail\x1b[0m")
            print("      [!] Something went wrong, check error status => %s" % str(e))
        s.close()
        return None
    else:
        if verbose:
            print("\x1b[1;92msuccess\x1b[0m")
        s.close()
        return True


def can_bind_to_interface_on_port(target, port, credentials, uuid, version, verbose=False):
    ncacn_target = r'ncacn_ip_tcp:%s[%d]' % (target, port)
    rpctransport = transport.DCERPCTransportFactory(ncacn_target)
    dce = rpctransport.get_dce_rpc()
    dce.set_credentials(credentials.username, credentials.password, credentials.domain, credentials.lmhash, credentials.nthash, None)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    if verbose:
        print("         [>] Connecting to %s ... " % ncacn_target, end="")
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
