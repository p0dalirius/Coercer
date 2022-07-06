#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MS_FSRVP.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import sys
from .RPCProtocol import RPCProtocol, DCERPCSessionError
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


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
