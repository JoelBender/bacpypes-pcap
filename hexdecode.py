#!/usr/bin/python

"""
This simple tool decodes a BACnet packet hex string.
"""

from bacpypes.debugging import ModuleLogger, xtob
from bacpypes.consolelogging import ArgumentParser

from bacpypes.analysis import decode_packet

# some debugging
_debug = 0
_log = ModuleLogger(globals())

#
#   __main__
#

# parse the command line arguments
parser = ArgumentParser(description=__doc__)
parser.add_argument("hexstring", type=str, help="hex string to decode")
parser.add_argument(
    "--ethernet", action="store_true", default=None, help="add ethernet header"
)
args = parser.parse_args()

if _debug:
    _log.debug("initialization")
if _debug:
    _log.debug("    - args: %r", args)

data = xtob(args.hexstring)

# add an Ethernet header
if args.ethernet:
    data = b"\0" * 14 + data

# decode the packet
pkt = decode_packet(data)
if pkt:
    pkt.debug_contents()
