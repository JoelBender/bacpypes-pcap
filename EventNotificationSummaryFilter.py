#!/usr/bin/python

"""
This application looks for confirmed event notifications and their corresponding
acknowledgements.  It prints out the client and server BACnet addresses and the
amount of time it took to acknowledge the event, and if there are any events
that went unacknowledged.

This application accepts the same --source, --destination, and --host options
as the other filters, and accepts the debugging options of other BACpypes
applications.
"""

from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import ArgumentParser

from bacpypes.pdu import Address
from bacpypes.analysis import trace, strftimestamp, Tracer
from bacpypes.apdu import ConfirmedEventNotificationRequest, SimpleAckPDU

try:
    from CSStat import Statistics
except ImportError:
    Statistics = lambda: None

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
filterSource = None
filterDestination = None
filterHost = None

# dictionary of pending requests
requests = {}

# all traffic
traffic = []

#
#   Traffic
#


class Traffic:
    def __init__(self, req):
        self.req = req
        self.resp = None

        self.ts = req._timestamp
        self.retry = 1


#
#   Match
#


@bacpypes_debugging
def Match(addr1, addr2):
    """Return true iff addr1 matches addr2."""
    if _debug:
        Match._debug("Match %r %r", addr1, addr2)

    if addr2.addrType == Address.localBroadcastAddr:
        # match any local station
        return (addr1.addrType == Address.localStationAddr) or (
            addr1.addrType == Address.localBroadcastAddr
        )
    elif addr2.addrType == Address.localStationAddr:
        # match a specific local station
        return (addr1.addrType == Address.localStationAddr) and (
            addr1.addrAddr == addr2.addrAddr
        )
    elif addr2.addrType == Address.remoteBroadcastAddr:
        # match any remote station or remote broadcast on a matching network
        return (
            (addr1.addrType == Address.remoteStationAddr)
            or (addr1.addrType == Address.remoteBroadcastAddr)
        ) and (addr1.addrNet == addr2.addrNet)
    elif addr2.addrType == Address.remoteStationAddr:
        # match a specific remote station
        return (
            (addr1.addrType == Address.remoteStationAddr)
            and (addr1.addrNet == addr2.addrNet)
            and (addr1.addrAddr == addr2.addrAddr)
        )
    elif addr2.addrType == Address.globalBroadcastAddr:
        # match a global broadcast address
        return addr1.addrType == Address.globalBroadcastAddr
    else:
        raise RuntimeError("invalid match combination")


#
#   ConfirmedEventNotificationSummary
#


@bacpypes_debugging
class ConfirmedEventNotificationSummary(Tracer):
    def __init__(self):
        if _debug:
            ConfirmedEventNotificationSummary._debug("__init__")
        Tracer.__init__(self, self.Filter)

    def Filter(self, pkt):
        if _debug:
            ConfirmedEventNotificationSummary._debug("Filter %r", pkt)
        global requests

        # apply the filters
        if filterSource:
            if not Match(pkt.pduSource, filterSource):
                if _debug:
                    ConfirmedEventNotificationSummary._debug("    - source filter fail")
                return
        if filterDestination:
            if not Match(pkt.pduDestination, filterDestination):
                if _debug:
                    ConfirmedEventNotificationSummary._debug(
                        "    - destination filter fail"
                    )
                return
        if filterHost:
            if (not Match(pkt.pduSource, filterHost)) and (
                not Match(pkt.pduDestination, filterHost)
            ):
                if _debug:
                    ConfirmedEventNotificationSummary._debug("    - host filter fail")
                return

        # check for notifications
        if isinstance(pkt, ConfirmedEventNotificationRequest):
            key = (pkt.pduSource, pkt.pduDestination, pkt.apduInvokeID)
            if key in requests:
                if _debug:
                    ConfirmedEventNotificationSummary._debug("    - retry")
                requests[key].retry += 1
            else:
                if _debug:
                    ConfirmedEventNotificationSummary._debug("    - new request")
                msg = Traffic(pkt)
                requests[key] = msg
                traffic.append(msg)

        # now check for acks
        elif isinstance(pkt, SimpleAckPDU):
            key = (pkt.pduDestination, pkt.pduSource, pkt.apduInvokeID)
            req = requests.get(key, None)
            if req:
                if _debug:
                    ConfirmedEventNotificationSummary._debug(
                        "    - matched with request"
                    )
                requests[key].resp = pkt

                # delete the request, it stays in the traffic list
                del requests[key]
            else:
                if _debug:
                    ConfirmedEventNotificationSummary._debug("    - unmatched")


#
#   __main__
#

# parse the command line arguments
parser = ArgumentParser(description=__doc__)
parser.add_argument("-s", "--source", nargs="?", type=str, help="source address")
parser.add_argument(
    "-d", "--destination", nargs="?", type=str, help="destination address"
)
parser.add_argument("--host", nargs="?", type=str, help="source or destination")
parser.add_argument("pcap", nargs="+", type=str, help="pcap file(s)")
args = parser.parse_args()

if _debug:
    _log.debug("initialization")
if _debug:
    _log.debug("    - args: %r", args)

# interpret the arguments
if args.source:
    filterSource = Address(args.source)
    if _debug:
        _log.debug("    - filterSource: %r", filterSource)
if args.destination:
    filterDestination = Address(args.destination)
    if _debug:
        _log.debug("    - filterDestination: %r", filterDestination)
if args.host:
    filterHost = Address(args.host)
    if _debug:
        _log.debug("    - filterHost: %r", filterHost)

# start out with no unmatched requests
requests = {}

# trace the file(s)
for fname in args.pcap:
    trace(fname, [ConfirmedEventNotificationSummary])

# dump everything
for msg in traffic:
    req = msg.req
    resp = msg.resp

    if resp:
        deltatime = "%8.2fms" % ((resp._timestamp - req._timestamp) * 1000,)
    else:
        deltatime = "-"

    print(
        "%s\t%s\t%s\t%8s\t%s\t%s\t%s\t%s"
        % (
            strftimestamp(req._timestamp),
            req.pduSource,
            resp.pduSource if resp else "-",
            deltatime,
            msg.retry if (msg.retry != 1) else "",
            req.eventObjectIdentifier,
            req.fromState,
            req.toState,
        )
    )
