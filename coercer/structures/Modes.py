#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Modes.py
# Author             : p0rtL (@p0rtL6)
# Date created       : 3 Dec 2024

from enum import Enum


class Modes(Enum):
    """
    Enum class Modes
    """

    COERCE = 0x01
    SCAN = 0x02
    FUZZ = 0x03
