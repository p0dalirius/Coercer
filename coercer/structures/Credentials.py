#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Credentials.py
# Author             : Podalirius (@podalirius_)
# Date created       : 16 Sep 2022

class Credentials(object):
    """
    Documentation for class Credentials
    """

    def __init__(self, username, password, domain, lmhash, nthash, doKerberos=False, kdcHost=None):
        super(Credentials, self).__init__()
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost

    def is_anonymous(self):
        """
        Function is_anonymous()
        Returns True if anonymous authentication is used False otherwise

        Returns:
        bool:anonymous
        """
        anonymous = False
        if self.username is None:
            anonymous = True
        elif len(self.username) == 0:
            anonymous = True
        else:
            anonymous = False
        return anonymous
