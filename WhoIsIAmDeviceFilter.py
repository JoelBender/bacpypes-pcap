#!/usr/bin/python

"""
Who-Is and I-Am Device Filter

Given a device identifier and a list of PCAP files, this application prints
a summary line of Who-Is packets such that the device should respond, and
the I-Am packets that are sent by the device.  This is useful for repeated
attempts to 'bind' where it fails, or where more than one device responds to
the request (which is bad) or the same device responds but it comes from
changing source addresses (which is really bad).
"""

from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import ArgumentParser

from bacpypes.pdu import Address
from bacpypes.analysis import trace, strftimestamp, Tracer
from bacpypes.apdu import WhoIsRequest, IAmRequest

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
filterSource = None
filterDestination = None
filterHost = None
filterDevice = None

#
#   Match
#

@bacpypes_debugging
def Match(addr1, addr2):
    """Return true iff addr1 matches addr2."""
    if _debug: Match._debug("Match %r %r", addr1, addr2)

    if (addr2.addrType == Address.localBroadcastAddr):
        # match any local station
        return (addr1.addrType == Address.localStationAddr) or (addr1.addrType == Address.localBroadcastAddr)
    elif (addr2.addrType == Address.localStationAddr):
        # match a specific local station
        return (addr1.addrType == Address.localStationAddr) and (addr1.addrAddr == addr2.addrAddr)
    elif (addr2.addrType == Address.remoteBroadcastAddr):
        # match any remote station or remote broadcast on a matching network
        return ((addr1.addrType == Address.remoteStationAddr) or (addr1.addrType == Address.remoteBroadcastAddr)) \
            and (addr1.addrNet == addr2.addrNet)
    elif (addr2.addrType == Address.remoteStationAddr):
        # match a specific remote station
        return (addr1.addrType == Address.remoteStationAddr) and \
            (addr1.addrNet == addr2.addrNet) and (addr1.addrAddr == addr2.addrAddr)
    elif (addr2.addrType == Address.globalBroadcastAddr):
        # match a global broadcast address
        return (addr1.addrType == Address.globalBroadcastAddr)
    else:
        raise RuntimeError("invalid match combination")

#
#   WhoIsIAmDevice
#

@bacpypes_debugging
class WhoIsIAmDevice(Tracer):

    def __init__(self):
        if _debug: WhoIsIAmDevice._debug("__init__")
        Tracer.__init__(self, self.Filter)

    def Filter(self, pkt):
        if _debug: WhoIsIAmDevice._debug("Filter %r", pkt)
        global requests

        # apply the filters
        if filterSource:
            if not Match(pkt.pduSource, filterSource):
                if _debug: WhoIsIAmDevice._debug("    - source filter fail")
                return
        if filterDestination:
            if not Match(pkt.pduDestination, filterDestination):
                if _debug: WhoIsIAmDevice._debug("    - destination filter fail")
                return
        if filterHost:
            if (not Match(pkt.pduSource, filterHost)) and (not Match(pkt.pduDestination, filterHost)):
                if _debug: WhoIsIAmDevice._debug("    - host filter fail")
                return

        # check for Who-Is
        if isinstance(pkt, WhoIsRequest):
            match = False
            if (pkt.deviceInstanceRangeLowLimit is None) or (pkt.deviceInstanceRangeHighLimit is None):
                match = True
            elif (pkt.deviceInstanceRangeLowLimit >= filterDevice) and (pkt.deviceInstanceRangeHighLimit <= filterDevice):
                match = True

            if match:
                print("[%d] %s WhoIs %-20s %-20s %8s %8s" % (
                    pkt._index + 1, strftimestamp(pkt._timestamp), 
                    pkt.pduSource, pkt.pduDestination,
                    pkt.deviceInstanceRangeLowLimit, pkt.deviceInstanceRangeHighLimit,
                    ))

        # check for I-Am
        elif isinstance(pkt, IAmRequest):

            if (pkt.iAmDeviceIdentifier[1] == filterDevice):
                print("[%d] %s IAm   %-20s %-20s" % (
                    pkt._index + 1, strftimestamp(pkt._timestamp),
                    pkt.pduSource, pkt.pduDestination,
                    ))


#
#   __main__
#

# parse the command line arguments
parser = ArgumentParser(description=__doc__)
parser.add_argument(
    "-s", "--source", nargs='?', type=str,
    help="source address",
    )
parser.add_argument(
    "-d", "--destination", nargs='?', type=str,
    help="destination address",
    )
parser.add_argument(
    "--host", nargs='?', type=str,
    help="source or destination",
    )
parser.add_argument(
    "device", nargs=1, type=int,
    help="device identifier",
    )
parser.add_argument(
    "pcap", nargs='+', type=str,
    help="pcap file(s)",
    )
args = parser.parse_args()

if _debug: _log.debug("initialization")
if _debug: _log.debug("    - args: %r", args)

# interpret the arguments
if args.source:
    filterSource = Address(args.source)
    if _debug: _log.debug("    - filterSource: %r", filterSource)
if args.destination:
    filterDestination = Address(args.destination)
    if _debug: _log.debug("    - filterDestination: %r", filterDestination)
if args.host:
    filterHost = Address(args.host)
    if _debug: _log.debug("    - filterHost: %r", filterHost)

# which device instance to look for
filterDevice = args.device[0]
if _debug: _log.debug("    - filterDevice: %r", filterDevice)

# trace the file(s)
for fname in args.pcap:
    trace(fname, [WhoIsIAmDevice])
