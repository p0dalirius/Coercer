#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MethodTypes.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

from enum import Enum


class MethodType(Enum):
    """
    Enum for defining different types of methods used in the protocol.

    This enumeration provides a way to categorize methods based on their type, allowing for easier identification and handling within the protocol. It includes a range of predefined types, including MICROSOFT_PROTOCOL and OTHER, which can be used to classify methods accordingly.
    """

    MICROSOFT_PROTOCOL = 0x01

    OTHER = 0xff


