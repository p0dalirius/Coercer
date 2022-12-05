#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MethodTypes.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

from enum import Enum


class MethodType(Enum):
    """
    Enum class MethodType
    """

    MICROSOFT_PROTOCOL = 0x01

    OTHER = 0xff


