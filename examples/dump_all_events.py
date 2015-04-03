#!/usr/bin/env python

__author__ = 'jgarman'


import sys
import argparse
import Queue
import os
import threading
import json

import logging
from cbapi2 import CbApi2

worker_queue = Queue.Queue(maxsize=50)


class EventWorker(threading.Thread):
    def __init__(self, basepath):
        self.basepath = basepath
        threading.Thread.__init__(self)

    def already_exists(self, pathname, item):
        try:
            procinfo = json.load(open(pathname, 'rb'))
            if procinfo['last_update'] == item.original_document['last_update']:
                return True
        except:
            pass

        return False

    def run(self):
        l = logging.getLogger('co.redcanary.get_events.worker_thread')
        l.setLevel(logging.INFO)

        while True:
            item = worker_queue.get()
            filename = str(item.id) + '-' + str(item.segment) + '.json'
            pathname = os.path.join(self.basepath, filename)

            if self.already_exists(pathname, item):
                l.info('already have %s' % filename)
            else:
                write_progress = 0
                try:
                    json.dump(item.original_document, open(pathname, 'wb'))
                    write_progress += 1
                except:
                    pass

                if not write_progress:
                    l.error(u'Could not grab {0:s}'.format(filename))
                elif write_progress == 1:
                    l.info(u'Grabbed {0:s}'.format(filename))
            worker_queue.task_done()


def dump_all_events(cb, destdir, query):
    try:
        os.makedirs(destdir)
    except:
        pass

    threads = []
    num_worker_threads = 10
    for i in range(num_worker_threads):
        t = EventWorker(destdir)
        t.daemon = True
        t.start()
        threads.append(t)

    for event in cb.process_search(query):
        worker_queue.put(event)

    worker_queue.join()


def main():
    parser = argparse.ArgumentParser(description="Grab all events from a Cb server")
    parser.add_argument('-d', '--destdir', action='store', help='Destination directory to place the events', default=os.curdir)

    parser.add_argument('-q', '--query', action='store', dest='query', help='Query string', default='')
    parser.add_argument('-v', action='store_true', dest='verbose', help='Enable verbose debugging messages',
                        default=False)
    parser.add_argument(action='store', nargs=1, dest='url', help='Cb server base URL', default='')
    parser.add_argument(action='store', nargs=1, dest='apikey', help='Cb server API key', default='')

    results = parser.parse_args()

    if results.verbose:
        l = logging.getLogger('co.redcanary')
        l.setLevel(logging.DEBUG)
    else:
        l = logging.getLogger('co.redcanary.get_events.worker_thread')
        l.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh = logging.FileHandler(os.path.join(results.destdir[0], 'log.txt'))
    fh.setFormatter(formatter)
    l.addHandler(ch)
    l.addHandler(fh)

    cb = CbApi2(results.url[0], results.apikey[0], ssl_verify=False)
    return dump_all_events(cb, results.destdir, results.query)


if __name__ == '__main__':
    sys.exit(main())

