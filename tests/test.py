import unittest

from nose.tools import *

from cbapi2 import CbApi2, CbNetConnEvent
import unittest

class test_CbApi2(unittest.TestCase):
    def setUp(self):
        # connect to the Cb API
        self.cb = CbApi2('http://172.16.112.184/', '070093f0c987ca0b5fc7a72fa467e995cf4930b4', ssl_verify=False,
                         debug=True)
        self.sample_proc = self.cb.process_search()[0]

    def testProcesses(self):
        # find all notepad processes with at least one filemod
        query = self.cb.process_search('process_name:notepad.exe filemod_count:[1 TO *]')

        # iterate over results
        for proc in query:
            # display all modloads for this process
            print '%s started at %s' % (proc.path, proc.start_time)
            print 'VirusTotal score:', proc.binary.virustotal.score
            print 'filemods:'
            for ml in proc.filemods:
                print ' ', ml.path

    def testAllEvents(self):
        query = self.cb.process_search('netconn_count:[1 TO *]')
        for proc in query:
            print proc
            for event in proc.all_events:
                print event

    def testRerunProcesses(self):
        # running the query again causes another RTT to the Cb server
        query = self.cb.process_search('process_name:notepad.exe filemod_count:[1 TO *]')

        # but we shouldn't see requests to the individual process events here
        # since they're cached
        for proc in query:
            print 'getting filemods again:'
            for ml in proc.filemods:
                print ' ', ml.path

    def testWriteBinary(self):
        proc = self.sample_proc

        print 'writing hash', proc.binary.md5sum, 'to /tmp/blah'
        open('/tmp/blah', 'wb').write(proc.binary.file.read())

        # print signing data
        if proc.binary.signed:
            print 'Process binary was signed; signing data was:', proc.binary.signing_data
        else:
            print 'Process binary was not signed:', proc.binary.signing_data

    def testAllEvents(self):
        print 'all events:'
        for event in self.sample_proc.all_events:
            print event.timestamp,
            if type(event) == CbNetConnEvent:
                print event.dns, event.ipaddr
            else:
                print event.path

    def testSlices(self):
        query = self.cb.process_search()
        assert_equal(query[1:1], [])
        assert_equal(len(query[1:2]), 1)
        assert_equal(len(query[:10]), 10)
