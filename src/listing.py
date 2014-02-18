#!/usr/bin/python

import os
import sys
import msgpack

import elliptics
from elliptics import Address

if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()
    parser.usage = "%prog [options] TYPE"
    parser.description = __doc__
    parser.add_option("-r", "--remote", action="store", dest="elliptics_remote", default="localhost:1025:2",
                      help="Elliptics node address [default: %default]")
    parser.add_option("-g", "--groups", action="store", dest="elliptics_groups", default="1,2,3",
                      help="Comma separated list of groups [default: all]")

    parser.add_option("-l", "--log", dest="elliptics_log", default='/dev/stdout', metavar="FILE",
                      help="Output log messages from library to file [default: %default]")
    parser.add_option("-L", "--log-level", action="store", dest="elliptics_log_level", default="1",
                      help="Elliptics client verbosity [default: %default]")

    parser.add_option("-w", "--wait-timeout", action="store", dest="wait_timeout", default="3600",
                      help="[Wait timeout for elliptics operations default: %default]")
    parser.add_option("-b", "--bucket", action="store_true", dest="bucket", default="testns",
                      help="Bucket name [default: %default]")

    (options, args) = parser.parse_args()


    try:
        elog = elliptics.Logger(options.elliptics_log, int(options.elliptics_log_level))
        node = elliptics.Node(elog)
        node.add_remote(options.elliptics_remote)

        session = elliptics.Session(node)
        session.groups = map(int, options.elliptics_groups.split(','))
	session.set_namespace(options.bucket)

	indexes = session.find_all_indexes([options.bucket + ".index"]).get()
	for idx in indexes:
		data = idx.indexes[0].data
		x = msgpack.unpackb(data)

		print idx.id, x
    except Exception as e:
	    print "Could not create elliptics node:", e


