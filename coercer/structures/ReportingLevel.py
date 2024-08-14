#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ReportingLevel.py
# Author             : Podalirius (@podalirius_)
# Date created       : 19 Sep 2022

from enum import Enum


class ReportingLevel(Enum):
    """
    Enum for defining the level of detail in reporting.

    This Enum provides a way to specify the level of detail in reporting, ranging from minimal (INFO) to most detailed (VERBOSE). The DEBUg level is reserved for debugging purposes and provides the highest level of detail.

    Attributes:
        INFO (int): Represents the minimum level of detail in reporting, providing basic information.
        VERBOSE (int): Represents a higher level of detail in reporting, providing more information than INFO.
        DEBUg (int): Represents the highest level of detail in reporting, intended for debugging purposes.
    """

    INFO = 1

    VERBOSE = 2

    DEBUg = 0xff