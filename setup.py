#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : setup.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jul 2022

import setuptools

long_description = """
<p align="center">
  A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through 9 methods.
  <br>
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/Coercer">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
</p>

## Features

 - [x] Automatically detects open SMB pipes on the remote machine.
 - [x] Calls one by one all the vulnerable RPC functions to coerce the server to authenticate on an arbitrary machine.
 - [x] Analyze mode with `--analyze`, which only lists the vulnerable protocols and functions listening, without performing a coerced authentication.
 - [x] Perform coerce attack on a list of targets from a file with `--targets-file`
 - [x] Coerce to a WebDAV target with `--webdav-host` and `--webdav-port`

## Usage

```
$ ./Coercer.py -h                                                                                                  

       ______                              
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v1.5.1
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

usage: Coercer.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [--hashes [LMHASH]:NTHASH] [--no-pass] [-v] [-a] [-k] [--dc-ip ip address] [-l LISTENER] [-wh WEBDAV_HOST] [-wp WEBDAV_PORT]
                  (-t TARGET | -f TARGETS_FILE) [--target-ip ip address]

Automatic windows authentication coercer over various RPC calls.

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username to authenticate to the endpoint.
  -p PASSWORD, --password PASSWORD
                        Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)
  -d DOMAIN, --domain DOMAIN
                        Windows domain name to authenticate to the endpoint.
  --hashes [LMHASH]:NTHASH
                        NT/LM hashes (LM hash can be empty)
  --no-pass             Don't ask for password (useful for -k)
  -v, --verbose         Verbose mode (default: False)
  -a, --analyze         Analyze mode (default: Attack mode)
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the
                        command line
  --dc-ip ip address    IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -t TARGET, --target TARGET
                        IP address or hostname of the target machine
  -f TARGETS_FILE, --targets-file TARGETS_FILE
                        IP address or hostname of the target machine
  --target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it

  -l LISTENER, --listener LISTENER
                        IP address or hostname of the listener machine
  -wh WEBDAV_HOST, --webdav-host WEBDAV_HOST
                        WebDAV IP of the server to authenticate to.
  -wp WEBDAV_PORT, --webdav-port WEBDAV_PORT
                        WebDAV port of the server to authenticate to.

```

## Coerced SMB authentication demonstration

Here is a video demonstration of the attack mode against a target:

https://user-images.githubusercontent.com/79218792/177647814-bb04f728-96bb-4048-a3ad-f83b250c05bf.mp4

## Coerced WebDAV authentication demonstration

If you want to trigger an HTTP authentication, you can use WebDAV with `--webdav-host` and the netdbios name of your attacking machine! Here is an example:

https://user-images.githubusercontent.com/79218792/178027554-a0b084d8-10af-401a-b54c-f33bec011fe2.mp4

## Example output

In attack mode (without `--analyze` option) you get the following output:

![](./.github/example.png)

After all the RPC calls, you get plenty of authentications in Responder:

![](./.github/hashes.png)

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits

 - [@topotam77](https://twitter.com/topotam77) for **PetitPotam** on [MS-EFSR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
 - [@topotam77](https://twitter.com/topotam77) and [@_nwodtuhs](https://twitter.com/_nwodtuhs) for **ShadowCoerce** on [MS-FSRVP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
 - [@filip_dragovic](https://twitter.com/filip_dragovic) for **DFSCoerce** on [MS-DFSNM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)


"""

with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [x.strip() for x in f.readlines()]

setuptools.setup(
    name="coercer",
    version="1.5.1",
    description="",
    url="https://github.com/p0dalirius/Coercer",
    author="Podalirius",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="podalirius@protonmail.com",
    packages=["coercer", "coercer.protocols", "coercer.utils"],
    package_data={'coercer': ['coercer/protocols/']},
    include_package_data=True,
    license="GPL2",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    entry_points={
        'console_scripts': ['Coercer=coercer.__main__:main']
    }
)
