#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : TestResults.py
# Author             : Podalirius (@podalirius_)
# Date created       : 19 Sep 2022

from enum import Enum


class TestResult(Enum):
    """
    Enum for defining the results of a test.

    This enumeration provides a way to categorize the outcomes of a test, including successful authentication attempts and various error conditions. It includes predefined values for common test results, allowing for easy identification and handling of different scenarios.

    Attributes:
        NO_AUTH_RECEIVED (int): Represents a test result where no authentication was received.
        SMB_AUTH_RECEIVED (int): Represents a test result where SMB authentication was received.
        HTTP_AUTH_RECEIVED (int): Represents a test result where HTTP authentication was received.
        NCA_S_UNK_IF (int): Represents a test result indicating an unknown interface.
        ERROR_BAD_NETPATH (int): Represents a test result indicating a bad network path.
        ERROR_INVALID_NAME (int): Represents a test result indicating an invalid name.
        RPC_X_BAD_STUB_DATA (int): Represents a test result indicating bad stub data.
        RPC_S_ACCESS_DENIED (int): Represents a test result indicating access denied.
        RPC_S_INVALID_BINDING (int): Represents a test result indicating an invalid binding.
        RPC_S_INVALID_NET_ADDR (int): Represents a test result indicating an invalid network address.
        SMB_STATUS_PIPE_DISCONNECTED (int): Represents a test result indicating a disconnected SMB pipe.
    """
    
    NO_AUTH_RECEIVED   = 0x0
    SMB_AUTH_RECEIVED  = 0x1
    HTTP_AUTH_RECEIVED = 0x2

    NCA_S_UNK_IF = 0x10001

    ERROR_BAD_NETPATH = 0x35
    ERROR_INVALID_NAME = 0x7b

    RPC_X_BAD_STUB_DATA = 0x20001
    RPC_S_ACCESS_DENIED = 0x5
    RPC_S_INVALID_BINDING = 0x6a6
    RPC_S_INVALID_NET_ADDR = 0x6ab

    SMB_STATUS_PIPE_DISCONNECTED = 0x30001

