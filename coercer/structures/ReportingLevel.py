#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ReportingLevel.py
# Author             : Podalirius (@podalirius_)
# Date created       : 19 Sep 2022

from enum import Enum


class ReportingLevel(Enum):
    """
    Enum class ReportingLevel
    """

    INFO = 1

    VERBOSE = 2

    DEBUg = 0xff