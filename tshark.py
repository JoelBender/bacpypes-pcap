#!/urs/bin/python

"""
tshark

There are debugging situations where there is no access to a GUI interface
like Wireshark and to be able to email simple capture data.  This application
parses the tshark output generated like this:

    $ sudo tshark -i eth0 -P -x -f 'udp port 47808'

And feeds that into the decoder.
"""

import sys
import re
import json

from bacpypes.debugging import ModuleLogger, xtob
from bacpypes.consolelogging import ArgumentParser

from bacpypes.analysis import decode_packet

# some debugging
_debug = 0
_log = ModuleLogger(globals())


sample = """
    1 0.000000000    10.0.1.93 -> 10.0.1.255   BACnet-APDU 66 Unconfirmed-REQ i-Am device,18 

0000  ff ff ff ff ff ff a4 4e 31 7e aa f4 08 00 45 00   .......N1~....E.
0010  00 34 e4 6d 40 00 40 11 3e f0 0a 00 01 5d 0a 00   .4.m@.@.>....]..
0020  01 ff ba c0 ba c0 00 20 53 5a 81 0b 00 18 01 20   ....... SZ..... 
0030  ff ff 00 ff 10 00 c4 02 00 00 12 22 04 00 91 00   ..........."....
0040  21 0f                                             !.
"""

tshark_re = re.compile("^[0-9]{4}  ([0-9a-f ][0-9a-f ] ){16}  ")


def parse_stream(sample_text):
    packet_data = ""
    for line in sample_text.splitlines():
        m = tshark_re.match(line)
        if not m:
            if packet_data:
                yield packet_data
                packet_data = ""
            continue

        offset = line[:4]
        if offset == "0000":
            if packet_data:
                yield packet_data
                packet_data = ""

        packet_data = packet_data + line[6:53].replace(" ", "")

    if packet_data:
        yield packet_data


def main():
    # parse the command line arguments
    parser = ArgumentParser(description=__doc__)
    args = parser.parse_args()
    if _debug:
        _log.debug("    - args: %r", args)

    for packet_data in parse_stream(sample):
        data = xtob(packet_data)
        packet = decode_packet(data)
        if not packet:
            continue

        x = {"apdu": packet.dict_contents()}
        json.dump(x, sys.stdout, indent=4)


if __name__ == "__main__":
    main()
