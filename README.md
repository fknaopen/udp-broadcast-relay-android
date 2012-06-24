UDP Broadcast Packet Relay (for Android)
=============================================================
This program listens for packets on a specified UDP broadcast.
When a packet is received, it sends that packet to all interfaces
on the local machine as though it originated from the original sender.

The primary purpose of this is to allow machines on the local network
to reach processes which have been bound to a specific interface
and as such do not receive broadcast packets.

Get Started
-------------------------------------------------------------
Get the source.

    git clone git://github.com/fknaopen/udp-broadcast-relay-android.git
    cp -pr udp-broadcast-relay-android ANDROID_BUILD_ROOT/external/udp_bcast_relay

Make modules.

    cd  ANDROID_BUILD_ROOT/.
    source build/envsetup.sh
    cd  ANDROID_BUILD_ROOT/external/.
    mm

Install. (push android device.)

    adb remount
    adb push ../../out/target/product/generic/system/bin/udp_bcast_relay /system/bin/.
 

USAGE
-------------------------------------------------------------

    udp_bcast_relay  [-d] packet-id portno [portno ...]
           -d : enables Debugging
    packet-id : 1-99

COMPATIBILITY
-------------------------------------------------------------
- I have tested this on Android 2.0 ...(-_-;
- but it should work on Linux a few modify.
  Modify header-include definition,
  and android-logger-macro (e.g. LOGW, LOGE).

EXAMPLE
-------------------------------------------------------------
    /system/bin/udp_bcast_relay 1 55001 55002 55003
Forward broadcast, 3 ports listen packets.
 
HISTORY
-------------------------------------------------------------
- 1.0 - 2012.6.24 Initial release
 
CREDITS
-------------------------------------------------------------
Based upon:

udp-broadcast-relay ; Relays UDP broadcasts to other networks, forging
    the sender address.
  Copyright (c) 2003 Joachim Breitner <mail@joachim-breitner.de>

udp_broadcast_fw ; Forwards UDP broadcast packets to all local
    interfaces as though they originated from sender
  Copyright (C) 2002  Nathan O'Sullivan

LICENSE
-------------------------------------------------------------
Copyright (c) 2012 Naohisa Fukuoka

This code is made available under the GPL.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
