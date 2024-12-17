#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : TransportType.py
# Author             : p0rtL (@p0rtL6)
# Date created       : 3 Dec 2024

from enum import Enum


class TransportType(Enum):
    """
    Enum class TransportType
    """
    NCACN_IP_TCP = "DCERPC port"
    NCAN_NP = "SMB named pipe"