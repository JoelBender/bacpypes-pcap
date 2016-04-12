#!/usr/bin/python

"""
Similar to the WhoIsRouterToNetworkSummaryFilter.py application, this
application searches through a PCAP file looking for routers that announce
themselves as routers to networks.  By matching this list with the BACnet
networks that are defined in a site, this can give a good indication of which
routers are misconfigured, and which BACnet devices are announcing themselves
as routers to the same network, which is really bad.

This application accepts the same --source, --destination, and --host options
as the other filters, and accepts the debugging options of other BACpypes
applications.
"""

from collections import defaultdict

from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import ArgumentParser

from bacpypes.pdu import Address
from bacpypes.analysis import trace, Tracer
from bacpypes.npdu import IAmRouterToNetwork

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
filterSource = None
filterDestination = None
filterHost = None

# dictionary of requests
requests = defaultdict(int)
networks = defaultdict(list)

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
#   IAmRouterToNetworkSummary
#

@bacpypes_debugging
class IAmRouterToNetworkSummary(Tracer):

    def __init__(self):
        if _debug: IAmRouterToNetworkSummary._debug("__init__")
        Tracer.__init__(self, self.Filter)

    def Filter(self, pkt):
        if _debug: IAmRouterToNetworkSummary._debug("Filter %r", pkt)
        global requests, networks

        # check for the packet type
        if not isinstance(pkt, IAmRouterToNetwork):
            return

        # apply the filters
        if filterSource:
            if not Match(pkt.pduSource, filterSource):
                if _debug: IAmRouterToNetworkSummary._debug("    - source filter fail")
                return
        if filterDestination:
            if not Match(pkt.pduDestination, filterDestination):
                if _debug: IAmRouterToNetworkSummary._debug("    - destination filter fail")
                return
        if filterHost:
            if (not Match(pkt.pduSource, filterHost)) and (not Match(pkt.pduDestination, filterHost)):
                if _debug: IAmRouterToNetworkSummary._debug("    - host filter fail")
                return

        # count it
        requests[pkt.pduSource] += 1
        networks[pkt.pduSource].append((pkt.iartnNetworkList))

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

# trace the file(s)
for fname in args.pcap:
    trace(fname, [IAmRouterToNetworkSummary])

# sort the result, descending order by count
items = requests.items()
items.sort(key=lambda x: x[1])

# print everything out
print("%-20s %5s" % ("Address", "Count"))
for key, count in items:
    print("%-20s %5d" % (key, count))

    # count the number of times of each network
    net_count = defaultdict(int)
    for subnet_list in networks[key]:
        for net in subnet_list:
            net_count[net] += 1

    # sort descending
    net_count = net_count.items()
    net_count.sort(key=lambda x: x[1])

    for net, count in net_count:
        print("    %5d %5d" % (net, count))
