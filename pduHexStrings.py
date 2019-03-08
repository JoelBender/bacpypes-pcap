#!/usr/bin/python

""" 
Example hex strings for testing decoding/encoding of PDUs.
These examples start at the BVLC layer.
"""

from bacpypes.debugging import xtob
from bacpypes.analysis import decode_packet

sample_strings = (
    # who is
    "81.0b.00.0c.01.20.ff.ff.00.ff.10.08",
    # who is with range
    "81.0b.00.12.01.20.ff.ff.00.ff.10.08.09.00.1b.02.71.00",
    # i am
    "81.04.00.23.0a.0a.00.01.ba.c0."
    "01.08.06.44.06.a9.fe.01.01.ba.c0."
    "10.00.c4.02.18.91.75.22.01.e0.91.03.21.10",
    # read property
    "81.0a.00.11.01.04.02.04.03.0c.0c.02.02.75.57.19.a7",
    # read property ack
    "81.0a.00.15.01.00.30.03.0c.0c.02.02.75.57.19.a7.3e.22.04.00.3f",
    # read property multiple
    "81.0a.00.1f."
    "01.24.06.44.06.a9.fe.01.01.ba.c0.ff.02.04.0d.0e.0c.02.18.91.75.1e.09.70.09.1c.1f",
    # read property multiple ack
    "81.0a.00.2b."
    "01.08.06.44.06.a9.fe.01.01.ba.c0.30.0d.0e.0c.02.18.91.75.1e.29.70.4e.91.00.4f.29.1c.4e.75.06.00.33.30.58.56.20.4f.1f",
    # error
    "81.0a.00.0d.01.00.50.08.0c.91.02.91.20.",
    # simple ack
    "81.0a.00.12.01.08.06.44.06.a9.fe.01.01.ba.c0.20.df.0f",
)

for sample in sample_strings:
    print(sample)

    # assume Ethernet header
    data = b"\0" * 14 + xtob(sample)

    # decode the packet
    pkt = decode_packet(data)
    if pkt:
        pkt.debug_contents()
    print("")
