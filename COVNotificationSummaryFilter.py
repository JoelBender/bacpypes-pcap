#!/usr/bin/python

"""
This application accepts the same --source, --destination, and --host options
as the other filters, and accepts the debugging options of other BACpypes
applications.
"""

from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import ArgumentParser

from bacpypes.pdu import Address
from bacpypes.analysis import trace, Tracer
from bacpypes.apdu import UnconfirmedCOVNotificationRequest

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
filterSource = None
filterDestination = None
filterHost = None

# dictionary of requests
requests = {}

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
#   COVNotificationSummary
#

@bacpypes_debugging
class COVNotificationSummary(Tracer):

    def __init__(self):
        if _debug: COVNotificationSummary._debug("__init__")
        Tracer.__init__(self, self.Filter)

    def Filter(self, pkt):
        if _debug: COVNotificationSummary._debug("Filter %r", pkt)
        global requests

        # apply the filters
        if filterSource:
            if not Match(pkt.pduSource, filterSource):
                if _debug: COVNotificationSummary._debug("    - source filter fail")
                return
        if filterDestination:
            if not Match(pkt.pduDestination, filterDestination):
                if _debug: COVNotificationSummary._debug("    - destination filter fail")
                return
        if filterHost:
            if (not Match(pkt.pduSource, filterHost)) and (not Match(pkt.pduDestination, filterHost)):
                if _debug: COVNotificationSummary._debug("    - host filter fail")
                return

        # check for notifications
        if isinstance(pkt, UnconfirmedCOVNotificationRequest):
            key = (pkt.pduSource, pkt.initiatingDeviceIdentifier[1], pkt.monitoredObjectIdentifier)
            if key in requests:
                requests[key] += 1
            else:
                requests[key] = 1


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

# start out with no requests
requests = {}

# trace the file(s)
for fname in args.pcap:
    trace(fname, [COVNotificationSummary])

# sort the result, descending order by count
items = requests.items()
items.sort(key=lambda x: x[1])

# print everything out
print("%-20s %8s %-15s %4s %5s" % ("Address", "Device", "Object", "", "Count"))
for key, count in items:
    print("%-20s %8s %-15s %4d %5d" % (key[0], key[1], key[2][0], key[2][1], count))
