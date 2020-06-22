#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import os
import sys
import struct
import socket
import rfc7822
import binascii
import time
from util import epoch_to_ntp_ts

import aes_siv

from ntp import NTPPacket, NTPExtensionField,  NTPExtensionFieldType
from nts import NTSClientPacketHelper, NTSCookie
from constants import *

import logging
import time
from logging.handlers import RotatingFileHandler


def create_rotating_log(path):
    """
    Creates a rotating log
    """
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.INFO)

    # add a rotating handler
    handler = RotatingFileHandler(path, maxBytes=200000000,
                                  backupCount=10)
    logger.addHandler(handler)

    return logger


def main():
    try:
        import configparser
    except ImportError:
        import ConfigParser as configparser

    log_file = "nts-ntp.log"
    logger = create_rotating_log(log_file)

    config = configparser.RawConfigParser()
    config.read('client.ini')

    nts_server = config.get('ntpv4', 'server').strip()
    nts_port = int(config.get('ntpv4', 'port'))

    if len(sys.argv) > 1:
        nts_server = sys.argv[1]
    if len(sys.argv) > 2:
        nts_port = int(sys.argv[2])

    c2s_key = binascii.unhexlify(config.get('keys', 'c2s'))
    s2c_key = binascii.unhexlify(config.get('keys', 's2c'))

    cookies = [ binascii.unhexlify(v) for k, v in sorted(config.items('cookies')) ]

    if not cookies:
        raise ValueError("no cookies in client.ini")

    import socket
    import os

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SO_TIMESTAMPNS = 35
    sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    sock.settimeout(1)

    cookie_len = len(cookies[0])

    req = NTSClientPacketHelper()
    req.transmit_timestamp = struct.unpack('Q', epoch_to_ntp_ts(time.time()).to_bytes(8, byteorder='little'))[0]

    unique_identifier = os.urandom(32)

    req.ext.append(NTPExtensionField(
        NTPExtensionFieldType.Unique_Identifier,
        unique_identifier))

    req.ext.append(NTPExtensionField(
        NTPExtensionFieldType.NTS_Cookie,
        cookies[0]))

    del cookies[0]

    if 1:
        # Throw away some of the cookies for testing
        cookies = cookies[:3]

    nr_cookies = len(cookies)

    req.pack_key = c2s_key
    req.enc_ext = [ ]

    for i in range(8 - nr_cookies - 1):
        req.ext.append(NTPExtensionField(NTPExtensionFieldType.NTS_Cookie_Placeholder, bytes(bytearray(cookie_len))))

    buf = req.pack()

    if 1:
        print(NTPPacket.unpack(buf))
        print()

    if 0:
        print(NTSServerPacket.unpack(buf, unpack_key = c2s_key))
        print()

    nts_addr = (nts_server, nts_port)
    print(nts_addr)
    sock.sendto(buf, nts_addr)

    try:
        data, ancdata, msg_flags, addr = sock.recvmsg(65536, 2048)
    except socket.timeout:
        print("Timeout")
        return
    if (len(ancdata) > 0):
        # print(len(ancdata),len(ancdata[0]),ancdata[0][0],ancdata[0][1],ancdata[0][2])
        # print('ancdata[0][2]:',type(ancdata[0][2])," - ",ancdata[0][2], " - ",len(ancdata[0][2]));
        for i in ancdata:
            print('ancdata: (cmsg_level, cmsg_type, cmsg_data)=(', i[0], ",", i[1], ", (", len(i[2]), ") ", i[2], ")");
            if (i[0] != socket.SOL_SOCKET or i[1] != SO_TIMESTAMPNS):
                continue
            tmp = (struct.unpack("iiii", i[2]))
            timestamp = tmp[0] + tmp[2] * 1e-9
            print("SCM_TIMESTAMPNS,", tmp, ", timestamp=", epoch_to_ntp_ts(timestamp))

    resp = NTSClientPacketHelper.unpack(data, unpack_key = s2c_key)
    print(resp)

    log = "{},{},{},{}".format(resp.origin_timestamp, resp.receive_timestamp, resp.transmit_timestamp,  epoch_to_ntp_ts(timestamp))

    logger.info(log)

    if resp.origin_timestamp != req.transmit_timestamp:
        raise ValueError("transmitted origin and received transmit timestamps do not match")
    if resp.unique_identifier != unique_identifier:
        raise ValueError("transmitted and received unique identifiers do not match")

    print("nts_cookies", len(resp.nts_cookies))
    print("enc_ext", len(resp.enc_ext))
    print("unath_ext", len(resp.unauth_ext))

    cookies.extend(resp.nts_cookies)

    # config.remove_section('cookies')
    # config.add_section('cookies')
    # for k, v in enumerate(cookies):
    #     config.set('cookies', str(k), binascii.hexlify(v).decode('ascii'))
    #
    # with open('client.ini', 'w') as f:
    #     config.write(f)

    time.sleep(1)

if __name__ == '__main__':
    try:
        while True:
            main()
    except KeyboardInterrupt:
        pass