=======================
Hornet
=======================

|travis| |coverage| |codehealth|

.. |coverage| image:: https://coveralls.io/repos/czardoz/hornet/badge.png?branch=master
                        :target: https://coveralls.io/r/czardoz/hornet?branch=master

.. |travis| image:: https://travis-ci.org/czardoz/hornet.png?branch=master
                      :target: https://travis-ci.org/czardoz/hornet

.. |codehealth| image:: https://landscape.io/github/czardoz/hornet/master/landscape.png
                          :target: https://landscape.io/github/czardoz/hornet/master
                          :alt: Code Health

Overview
=========

Hornet is aimed to be a medium interaction SSH Honeypot, that supports multiple virtual
hosts. Each virtual host is configured independently, and gets its own sandboxed filesystem.
Hornet allows interactions across hosts, meaning that the attacker may login to one host
from another (using the ssh command). A Hornet instance *must* contain a default host,
which serves as a launchpad to log into the other hosts. Any configured host can be set
to default with a simple configuration change.

At a high level, Hornet can be visualized to be working according to the following diagram:

.. code-block::

                                                   +-------------+
                                                   | VirtualHost |
                                +----------------> |             |
                                |                  |     One     |
                                |                  +------+------+
                                |                         ^
                                |                         |
                                |                         |
                                v                         v
                       +--------+----+             +------+------+
                       |   Default   |             | VirtualHost |
    Attacker+--------> |             | <---------> |             |
                       | VirtualHost |             |     One     |
                       +--------+----+             +------+------+
                                ^                         ^
                                |                         |
                                |                         |
                                |                         v
                                |                  +------+------+
                                |                  | VirtualHost |
                                +----------------> |             |
                                                   |     One     |
                                                   +-------------+

The double ended arrows signify possible interaction, through commands
such as ``ssh``, ``ping``, etc.

Each VirtualHost has the following configurable attributes:

* Hostname
* IP Address
* Sandboxed Filesystem
* User Pool
* DNS server (common across all VirtualHosts)
* Shell environment parameters (such as ``$PATH``)


Supported Commands
====================

Hornet currently supports the following commands:

* ``cd``
* ``ls``
* ``echo``
* ``ssh``
* ``logout``
* ``pwd``
* ``ifconfig``

Installation
==============

Installing is simple,

.. code-block::

    $ pip install git+https://github.com/czardoz/hornet.git

And since the latest version of telnetsrvlib on GitHub is super cool

.. code-block::

    $ pip install --upgrade git+https://github.com/ianepperson/telnetsrvlib.git#egg=telnetsrv-0.4.1

Usage
=======

Create a directory anywhere

.. code-block::

    $ mkdir ~/honeypot

Initialize Hornet

.. code-block::

    $ cd honeypot
    $ hornet -v

You should see something like this (ignore the errors):

.. code-block::

    2015-01-31 19:34:19,624 [INFO] (root) Starting Hornet, version: 0.0.1
    2015-01-31 19:34:19,624 [INFO] (hornet.main) Config file /tmp/honeypot/config.json not found, copying default
    2015-01-31 19:34:19,625 [DEBUG] (hornet.common.config) Default host set to: test02
    2015-01-31 19:34:19,625 [INFO] (hornet.main) Creating directory /tmp/honeypot/vhosts for virtual host filesystems
    2015-01-31 19:34:19,628 [ERROR] (hornet.core.host) IP address for test01 is not specified in the config file (or is "null")
    2015-01-31 19:34:19,628 [INFO] (hornet.core.host) Assigned random IP 192.168.0.103 to host test01
    2015-01-31 19:34:19,633 [ERROR] (hornet.core.host) IP Address 192.168.0.443 for test03 is not valid for the specified network
    2015-01-31 19:34:19,633 [INFO] (hornet.core.host) Assigned random IP 192.168.0.27 to host test03
    2015-01-31 19:34:19,640 [INFO] (hornet.main) SSH server listening on 127.0.0.1:59866

Once you get it working, you can set about configuring it. Hit `Ctrl+C` to stop the honeypot.

.. code-block::

    ...
    2015-01-31 19:34:19,640 [INFO] (hornet.main) SSH server listening on 127.0.0.1:59866
    ^CKeyboardInterrupt
    2015-01-31 19:40:58,419 [INFO] (root) Quitting
    2015-01-31 19:40:58,419 [DEBUG] (root) Stopping the server

Now, you'll see a ``config.json`` created in the current directory.

.. code-block::

    $ cat config.json
    {
        "port": 0,
        "host": "127.0.0.1",
        "key_file": "test_server.key",
        "network": {
            "network_ip": "192.168.0.0/24",
            "dns_server": "192.168.0.2",
            "gateway": "192.168.0.1"
        },
        "virtual_hosts": [
            {
                "hostname": "test02",
                "valid_logins": {
                    "mango": "apple",
                    "vstfpd": "1q2w3e4r",
                    "testuser": "testpassword"
                },
                "env": {
                    "BROWSER": "firefox",
                    "EDITOR": "gedit",
                    "SHELL": "/bin/bash",
                    "PAGER": "less"
                },
                "default": true,
                "ip_address": "192.168.0.232"
            },
            {
                "hostname": "test03",
                ...
                "ip_address": "192.168.0.443"
            }
        ]
    }

Edit it according to your wish. You'll also see a ``vhosts/`` directory.
Inside it are the sandbox filesystems for each VirtualHost (as defined in
the config file). These filesystems can be populated with any files you
wish.

You can now restart the honeypot:

.. code-block::

    $ hornet -v


Careful!
============

Hornet is under development, and should not be used for production purposes
yet. There are a fair amount of bugs, and perhaps security risks. Know what
you're doing!
