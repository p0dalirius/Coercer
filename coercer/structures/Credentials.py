#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Credentials.py
# Author             : Podalirius (@podalirius_)
# Date created       : 16 Sep 2022


import re
import binascii
 

class Credentials(object):
    """
    Documentation for class Credentials
    """

    # Identity
    domain = None
    username = None
    password = None
    # Hashes
    nt_hex = ""
    nt_raw = ""
    lm_hex = ""
    lm_raw = ""
    # Kerberos
    use_kerberos = False
    aesKey = None
    kdcHost = None

    def __init__(self, domain, username, password, hashes=None, use_kerberos=False, aesKey=None, kdcHost=None):
        super(Credentials, self).__init__()
        # Identity
        self.domain = domain
        self.username = username
        self.password = password
        # Hashes
        self.nt_hex = ""
        self.nt_raw = ""
        self.lm_hex = ""
        self.lm_raw = ""
        self.set_hashes(hashes=hashes)
        # Kerberos
        self.use_kerberos = use_kerberos
        self.kdcHost = kdcHost
        self.aesKey = aesKey

    def set_hashes(self, hashes):
        """
        Sets the LM and NT hashes for the credentials.

        This method parses the provided hash string and sets the LM and NT hash values accordingly.
        If the hash string is valid and contains both LM and NT hashes, they are set directly.
        If only one hash is provided, the other is set to its default value.
        If the hash string is None or invalid, both hashes are set to None.

        Args:
            hashes (str): A string containing LM and NT hashes separated by a colon.
        """

        self.nt_hex = ""
        self.nt_raw = ""
        self.lm_hex = ""
        self.lm_raw = ""

        lm_hash_value, nt_hash_value = "", ""

        if hashes is not None:
            matched = re.match("([0-9a-f]{32})?(:)?([0-9a-f]{32})?", hashes.strip().lower(),  re.IGNORECASE)
            match_lm_hash, _, match_nt_hash = matched.groups()
            if match_lm_hash is None and match_nt_hash is not None:
                self.lm_hex = "aad3b435b51404eeaad3b435b51404ee"
                self.lm_raw = binascii.unhexlify(self.lm_hex)
                self.nt_hex = match_nt_hash
                self.nt_raw = binascii.unhexlify(match_nt_hash)
            elif match_lm_hash is not None and match_nt_hash is None:
                self.lm_hex = match_lm_hash
                self.lm_raw = binascii.unhexlify(match_lm_hash)
                self.nt_hex = "31d6cfe0d16ae931b73c59d7e0c089c0"
                self.nt_raw = binascii.unhexlify(self.nt_hex)
            else:
                self.lm_hex = match_lm_hash
                self.lm_raw = binascii.unhexlify(match_lm_hash)
                self.nt_hex = match_nt_hash
                self.nt_raw = binascii.unhexlify(match_nt_hash)

        return lm_hash_value, nt_hash_value


    def is_anonymous(self):
        """
        Determines if the credentials are anonymous.

        This method checks if the username is None or an empty string to determine if the credentials are anonymous.

        Returns:
            bool: True if the credentials are anonymous, False otherwise.
        """
        
        anonymous = False

        if self.username is None:
            anonymous = True
        elif len(self.username) == 0:
            anonymous = True
        else:
            anonymous = False

        return anonymous

    def canPassTheHash(self):
        """
        Determines if the current credentials can be used for a pass-the-hash attack.

        This method checks if both LM and NT hashes are available and not None. If both hashes are set,
        it indicates that the credentials may be used for a pass-the-hash attack.

        Returns:
            bool: True if both LM and NT hashes are available, False otherwise.
        """

        return bool(
            (self.nt_hex is not None)
            and (self.nt_raw is not None)
            and (self.lm_hex is not None)
            and (self.lm_raw is not None)
        )

    def __dict__(self):
        return {
            "domain": self.domain,
            "username": self.username,
            "password": self.password,
            "hashes": {
                "lm_hex": self.lm_hex,
                "nt_hex": self.nt_hex
            },
            "use_kerberos": self.use_kerberos,
            "aesKey": self.aesKey,
            "kdcHost": self.kdcHost
        }
    
    def __repr__(self):
        return f"<Credentials for '{self.domain}\\{self.username}'>"
