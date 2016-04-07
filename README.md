# BACpypes-pcap

A set of applications for analyzing BACnet traffic in pcap files based on BACpypes.
To use these applications, first install BACpypes from PyPI:

    $ pip install bacpypes

or

    $ easy_install bacpypes

Then run them by feeding them the name of a `pcap` file that was created using
tools like (Wireshark)[https://www.wireshark.org/] or 
(daemonlogger)[https://sourceforge.net/projects/daemonlogger/].  Most of the
applications have options that pre-filter packets based on the source address,
destination address very similar to Wireshark display filters, except these
filters understand BACnet addresses.


