import csv
from functools import total_ordering
import urllib
import time

# json encoding & decoding
import yaml
from yaml import Loader, SafeLoader

import cjson

from datetime import datetime
import struct
import socket
from zipfile import ZipFile
from cStringIO import StringIO
import base64
import requests
from collections import namedtuple
from distutils.version import LooseVersion
import urlparse

from LRUCache import lrumemoized

import logging

__author__ = 'jgarman'

cb_datetime_format = "%Y-%m-%d %H:%M:%S.%f"
# NOTE: solr_datetime_format changed in Cb 4.1 to include microseconds
solr_datetime_format = "%Y-%m-%dT%H:%M:%S.%fZ"
sign_datetime_format = "%Y-%m-%dT%H:%M:%SZ"

logging.getLogger('co.redcanary.cbapi2').addHandler(logging.NullHandler())

# disable urllib3's constant warnings about turning off SSL certificate
# validation
requests.packages.urllib3.disable_warnings()


windows_rights_dict = {
    0x00100000L: 'SYNCHRONIZE',
    0x00080000L: 'WRITE_OWNER',
    0x00040000L: 'WRITE_DAC',
    0x00020000L: 'READ_CONTROL',
    0x00010000L: 'DELETE',
    0x00000001L: 'PROCESS_TERMINATE',
    0x00000002L: 'PROCESS_CREATE_THREAD',
    0x00000004L: 'PROCESS_SET_SESSIONID',
    0x00000008L: 'PROCESS_VM_OPERATION',
    0x00000010L: 'PROCESS_VM_READ',
    0x00000020L: 'PROCESS_VM_WRITE',
    0x00000040L: 'PROCESS_DUP_HANDLE',
    0x00000080L: 'PROCESS_CREATE_PROCESS',
    0x00000100L: 'PROCESS_SET_QUOTA',
    0x00000200L: 'PROCESS_SET_INFORMATION',
    0x00000400L: 'PROCESS_QUERY_INFORMATION',
    0x00000800L: 'PROCESS_SUPEND_RESUME',
    0x00001000L: 'PROCESS_QUERY_LIMITED_INFORMATION'
}
r_windows_rights_dict = dict((value, key) for key, value in windows_rights_dict.iteritems())


class CbAPIError(Exception):
    def __init__(self, r):
        self.request = r
        self.message = 'HTTP error code %d (%s)' % (r.status_code, ' / '.join(r.content.split('\n')))

    def __str__(self):
        return self.message


"""Create a Cb 4.2-style GUID from components"""


def create_42_guid(sensor_id, proc_pid, proc_createtime):
    full_guid = struct.pack('>IIQ', sensor_id, proc_pid, proc_createtime).encode('hex')
    return '%s-%s-%s-%s-%s' % (full_guid[:8], full_guid[8:12], full_guid[12:16],
                               full_guid[16:20], full_guid[20:])


def parse_42_guid(guid):
    guid_parts = guid.split('-')
    return struct.unpack('>IIQ', ''.join(guid_parts)[:32].decode('hex'))


def convert_to_solr(dt):
    return dt.strftime(solr_datetime_format)


# TODO: change these to use dateutil.parser (see http://labix.org/python-dateutil)
def convert_from_solr(s):
    if s == -1:
        # special case for invalid processes
        return datetime.fromtimestamp(0)

    try:
        return datetime.strptime(s, solr_datetime_format)
    except ValueError:
        # try interpreting the timestamp without the milliseconds
        return datetime.strptime(s, sign_datetime_format)


def convert_from_cb(s):
    # hack: we strip off the timezone if it exists
    # by simply cutting off the string by 26 characters
    # 2014-06-03 10:14:14.637964

    if not s or s == -1:
        # special case for invalid processes
        return datetime.fromtimestamp(0)

    s = s[:26]
    return datetime.strptime(s, cb_datetime_format)


def get_constants(prefix):
    """Create a dictionary mapping socket module constants to their names."""
    return dict((getattr(socket, n), n)
                for n in dir(socket)
                if n.startswith(prefix)
    )


protocols = get_constants("IPPROTO_")


@total_ordering
class CbEvent(object):
    def __init__(self, parent_process, timestamp, sequence, event_data):
        self.timestamp = timestamp
        self.parent = parent_process
        self.sequence = sequence
        self.__dict__.update(event_data)

        self.event_type = u'Generic Cb event'
        self.stat_titles = ['timestamp']

    def __lt__(self, other):
        return self.timestamp < other.timestamp

    def __unicode__(self):
        ret = '%s:\n' % self.event_type
        ret += u'\n'.join(['%-20s : %s' %
                           (a, unicode(self.__getattribute__(a))) for a in self.stat_titles])

        return ret

    def __str__(self):
        return self.__unicode__().encode('utf-8')

    @property
    def tamper_event(self):
        return getattr(self, 'tamper_flag', False)


class CbModLoadEvent(CbEvent):
    def __init__(self, parent_process, timestamp, sequence, event_data, binary_data=None):
        super(CbModLoadEvent,self).__init__(parent_process, timestamp, sequence, event_data)
        self.event_type = u'Cb Module Load event'
        self.stat_titles.extend(['md5', 'path'])

        self.binary_data = binary_data

    @property
    def binary(self):
        return getBinaryByMd5(self.parent.cb, self.md5, initial_data=self.binary_data)

    @property
    def is_signed(self):
        return self.binary.signed

class CbFileModEvent(CbEvent):
    def __init__(self, parent_process, timestamp, sequence, event_data):
        super(CbFileModEvent,self).__init__(parent_process, timestamp, sequence, event_data)
        self.event_type = u'Cb File Modification event'
        self.stat_titles.extend(['type', 'path', 'filetype', 'md5'])


class CbRegModEvent(CbEvent):
    def __init__(self, parent_process, timestamp, sequence, event_data):
        super(CbRegModEvent,self).__init__(parent_process, timestamp, sequence, event_data)
        self.event_type = u'Cb Registry Modification event'
        self.stat_titles.extend(['type', 'path'])


class CbNetConnEvent(CbEvent):
    def __init__(self, parent_process, timestamp, sequence, event_data):
        super(CbNetConnEvent,self).__init__(parent_process, timestamp, sequence, event_data)
        self.event_type = u'Cb Network Connection event'
        self.stat_titles.extend(['dns', 'ipaddr', 'port', 'protocol', 'direction'])


class CbChildProcEvent(CbEvent):
    def __init__(self, parent_process, timestamp, sequence, event_data):
        super(CbChildProcEvent,self).__init__(parent_process, timestamp, sequence, event_data)
        self.event_type = u'Cb Child Process event'
        self.stat_titles.extend(['procguid', 'pid', 'path', 'md5'])

    @property
    def proc(self):
        return getProcessById(self.parent.cb, self.procguid, 1)


class CbCrossProcEvent(CbEvent):
    def __init__(self, parent_process, timestamp, sequence, event_data):
        super(CbCrossProcEvent,self).__init__(parent_process, timestamp, sequence, event_data)
        self.event_type = u'Cb Cross Process event'
        self.stat_titles.extend(['type', 'privileges', 'target_md5', 'target_path'])

    @property
    def target_proc(self):
        return getProcessById(self.parent.cb, self.target_procguid, 1)

    def has_permission(self, perm):
        if perm in r_windows_rights_dict:
            if (self.privilege_code & r_windows_rights_dict[perm]) == r_windows_rights_dict[perm]:
                return True
            else:
                return False
        raise KeyError(perm)

    def has_permissions(self, perms):
        for perm in perms:
            if not self.has_permission(perm):
                return False
        return True


class CbDocument(object):
    def __init__(self, cb):
        self.cb = cb
        self.full_init = False
        self.info = {}
        self.document_type = u'Generic Cb document'
        self.stat_titles = ['url']

    def _retrieve_cb_info(self):
        pass

    def __getattr__(self, attrname):
        # retrieve any unknown attribute from the original document
        if attrname.startswith('_'):
            return

        out = self._attribute(attrname)
        if out:
            return out
        else:
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, attrname))

    def _attribute(self, attrname, default=None):
        if self.info.has_key(attrname):
            # workaround for Cb where parent_unique_id is returned as null
            # string as part of a query result. in this case we need to do a
            # full_init. TODO: add this to quirks when this is fixed by Cb.
            if attrname in ['parent_unique_id',
                            'parent_name',
                            'parent_md5'] and not self.full_init:
                self._retrieve_cb_info()
            else:
                return self.info[attrname]

        if not self.full_init:
            # fill in info from Cb
            self._retrieve_cb_info()

        if self.info.has_key(attrname):
            return self.info[attrname]

        return default

    def __unicode__(self):
        ret = '%s:\n' % self.document_type
        ret += u'\n'.join(['%-20s : %s' %
                           (a, unicode(getattr(self, a))) for a in self.stat_titles])

        return ret

    def __str__(self):
        return self.__unicode__().encode('utf-8')

    @property
    def original_document(self):
        if not self.full_init:
            self._retrieve_cb_info()

        return self.info

    def to_html(self):
        ret = u"<h3>%s</h3>" % self.document_type
        ret += u"<table><tr><th>Key</th><th>Value</th></tr>\n"
        for a in self.stat_titles:
            ret += '<tr><td><b>%s</b></td><td>%s</td></tr>\n' % (a, unicode(getattr(self, a)))
        ret += u'</table>'

        return ret

    def _repr_html_(self):
        return ('<div style="max-height:1000px;'
                'max-width:1500px;overflow:auto;">\n' +
                self.to_html() + '\n</div>')


class CbSensor(CbDocument):
    NetworkAdapter = namedtuple('NetworkAdapter', ['macaddr', 'ipaddr'])
    urlobject = '/api/v1/sensor'

    def __init__(self, cb, sensor_id, initial_data=None):
        super(CbSensor,self).__init__(cb)
        self.id = int(sensor_id)
        self.document_type = 'Cb Sensor Document'
        self.stat_titles.extend(['hostname', 'build_version_string', 'clock_delta'])

        if initial_data:
            self.info = dict(initial_data)

    def _retrieve_cb_info(self):
        self.info = self.cb._sensor_info(self.id)
        self.full_init = True

    @property
    def status(self):
        return self._attribute('status', 'Offline')

    @property
    def clock_delta(self):
        d = self._attribute('clock_delta', 0)
        if not d:
            return 0
        else:
            return int(d)

    @property
    def dns_name(self):
        return self._attribute('computer_dns_name', '')

    @property
    def hostname(self):
        return self._attribute('computer_name', '')

    @property
    def last_checkin_time(self):
        return convert_from_cb(self._attribute('last_checkin_time', -1))

    @property
    def last_update(self):
        return convert_from_cb(self._attribute('last_update', -1))

    @property
    def network_adapters(self):
        out = []
        for adapter in self._attribute('network_adapters', '').split('|'):
            parts = adapter.split(',')
            if len(parts) == 2:
                out.append(CbSensor.NetworkAdapter._make([':'.join(a+b for a,b in zip(parts[1][::2], parts[1][1::2])),
                                                          parts[0]]))
        return out

    @property
    def os(self):
        return self._attribute('os_environment_display_string')

    @property
    def registration_time(self):
        return convert_from_cb(self._attribute('registration_time', -1))

    @property
    def sid(self):
        return self._attribute('computer_sid')

    # TODO: this URL end point doesn't actually work.
    @property
    def url(self):
        return '{0:s}/#/host/{1:d}'.format(self.cb.url, self.id)

    # TODO: properly handle the stats api routes
    @property
    def queued_stats(self):
        return self.cb._do_request('%s/%d/queued' % (CbSensor.urlobject, self.id)).json()

    @property
    def activity_stats(self):
        return self.cb._do_request('%s/%d/activity' % (CbSensor.urlobject, self.id)).json()


class CbBinary(CbDocument):
    VirusTotal = namedtuple('VirusTotal', ['score', 'link'])
    SigningData = namedtuple('SigningData', ['result', 'publisher', 'issuer', 'subject', 'sign_time', 'program_name'])
    VersionInfo = namedtuple('VersionInfo', ['file_desc', 'file_version', 'product_name', 'product_version',
                                             'company_name', 'legal_copyright', 'original_filename'])
    FrequencyData = namedtuple('FrequencyData', ['computer_count', 'process_count', 'all_process_count',
                                                 'module_frequency'])

    urlobject = '/api/v1/binary'
    default_sort = None

    def __init__(self, cb, md5sum, initial_data=None):
        super(CbBinary,self).__init__(cb)

        self.md5sum = md5sum
        self._frequency = None
        self.document_type = 'Cb Binary Document'
        self.stat_titles.extend(['md5sum', 'size'])

        if initial_data:
            self.info = dict(initial_data)

    @staticmethod
    def new_object(cb, item):
        return getBinaryByMd5(cb, item['md5'], initial_data=item)

    @property
    def url(self):
        return '{0:s}/#binary/{1:s}'.format(self.cb.url, self.md5sum)

    @property
    def frequency(self):
        if not self._frequency:
            frequency = self.cb._binary_frequency(self.md5sum)
            hostCount = frequency.get('hostCount', 0)
            globalCount = frequency.get('globalCount', 0)
            numDocs = frequency.get('numDocs', 0)
            if numDocs == 0:
                frequency_fraction = 0.0
            else:
                frequency_fraction = float(globalCount) / float(numDocs)

            # TODO: frequency calculated over number of hosts rather than number of processes
            self._frequency = CbBinary.FrequencyData._make([hostCount, globalCount, numDocs,
                                                            frequency_fraction])

        return self._frequency

    def _retrieve_cb_info(self):
        if self.md5sum:
            try:
                self.info = self.cb._binary_summary(self.md5sum)
            except:
                # TODO: log this event
                pass
        self.full_init = True

    @property
    def file(self):
        z = StringIO(self.cb._get_binary(self.md5sum))
        zf = ZipFile(z)
        fp = zf.open('filedata')
        return fp

    @property
    def is_exe(self):
        return self._attribute('is_executable_image', False)

    @property
    def observed_filenames(self):
        return self._attribute('observed_filename', [])

    @property
    def size(self):
        return long(self._attribute('orig_mod_len', 0))

    @property
    def copied_size(self):
        return long(self._attribute('copied_mod_len', 0))

    @property
    def is_64bit(self):
        return bool(self._attribute('is_64bit', False))

    @property
    def version_info(self):
        return CbBinary.VersionInfo._make([self._attribute('file_desc'), self._attribute('file_version'),
                                           self._attribute('product_name'), self._attribute('product_version'),
                                           self._attribute('company_name'), self._attribute('legal_copyright'),
                                           self._attribute('original_filename')])

    # Returns True if the binary contains a valid digital signature.
    # Returns False if the binary has no digital signature, if the signature is expired or otherwise
    # distrusted.
    @property
    def signed(self):
        if self._attribute('digsig_result') == 'Signed':
            return True
        else:
            return False

    @property
    def signing_data(self):
        digsig_sign_time = self._attribute('digsig_sign_time')
        if digsig_sign_time:
            digsig_sign_time = datetime.strptime(digsig_sign_time, sign_datetime_format)

        return CbBinary.SigningData._make([self._attribute('digsig_result'),
                                           self._attribute('digsig_publisher'),
                                           self._attribute('digsig_issuer'),
                                           self._attribute('digsig_subject'),
                                           digsig_sign_time,
                                           self._attribute('digsig_prog_name')])

    @property
    def virustotal(self):
        virustotal_score = self._attribute('alliance_score_virustotal')
        if virustotal_score:
            ret = CbBinary.VirusTotal._make([int(virustotal_score), self._attribute('alliance_link_virustotal')])
        else:
            ret = CbBinary.VirusTotal._make([0, ''])
        return ret

    @property
    def icon(self):
        icon = ''
        try:
            icon = self._attribute('icon')
            if not icon:
                icon = ''
        except:
            pass

        return base64.b64decode(icon)


class CbDocumentQuery(object):
    def __init__(self, query, doc_class, cb):
        self.query = query
        self.doc_class = doc_class
        self.cb = cb
        self.sort_by = self.doc_class.default_sort

        # TODO: this should be subject to a TTL
        self.count_valid = False
        self.total_results = 0

    def __iter__(self):
        return self._query()

    def __getitem__(self, item):
        if isinstance(item, slice):
            if item.step and item.step > 1:
                raise ValueError("steps not supported")

            start = 0
            stop = 0
            if item.start:
                start = item.start
            if item.start and item.stop:
                if item.stop <= item.start:
                    return []
                stop = item.stop - item.start
            if not item.start and item.stop:
                stop = item.stop

            try:
                return list(self._query(start, stop))
            except StopIteration:
                return []
        elif isinstance(item, int):
            if item < 0:
                raise ValueError("negative indices not supported")

            try:
                return self._query(item, 1).next()
            except StopIteration:
                return None
        else:
            raise TypeError("invalid type")

    def __len__(self):
        if self.count_valid:
            return self.total_results
        return self._count()

    def sort(self, new_sort):
        new_sort = new_sort.strip()
        if len(new_sort) == 0:
            self.sort_by = None
        else:
            self.sort_by = new_sort
        return self

    def _query(self, start=0, numrows=0):
        for item in self._search(start=start, rows=numrows):
            yield self.doc_class.new_object(self.cb, item)

    def _count(self):
        self.total_results = self.cb._count(self.doc_class.urlobject, self.query)
        self.count_valid = True
        return self.total_results

    def _search(self, start=0, rows=0, perpage=100):
        # iterate over total result set, 100 at a time
        args = self.cb._default_args
        args['start'] = start
        if self.sort_by:
            args['sort'] = self.sort_by
        if rows:
            args['rows'] = min(rows, perpage)
        else:
            args['rows'] = perpage
        current = start
        numrows = 0

        if self.query:
            args['q'] = self.query
        else:
            args['q'] = ''

        still_querying = True

        while still_querying:
            r = self.cb._do_request(self.doc_class.urlobject, args)

            result = self.cb._decode_json(r)

            self.total_results = result.get('total_results')
            self.count_valid = True

            for item in result.get('results'):
                yield item
                current += 1
                numrows += 1
                if rows and numrows == rows:
                    still_querying = False
                    break

            args['start'] = current

            if current >= self.total_results:
                break


class CbProcess(CbDocument):
    urlobject = '/api/v1/process'
    default_sort = 'last_update desc'

    def __init__(self, cb, procguid, segment, initial_data=None):
        super(CbProcess,self).__init__(cb)

        try:
            self.id = int(procguid)
        except ValueError:
            # TODO: this is a hack to strip off the segment id. We should normalize this
            # properly.
            self.id = procguid[:36]

        self.segment = int(segment)
        self.document_type = 'Cb Process Document'
        self.stat_titles.extend(['hostname', 'username', 'cmdline', 'path'])

        if initial_data:
            # fill in data object for performance
            self.info = dict(initial_data)

    @staticmethod
    def new_object(cb, item):
        # TODO: do we ever need to evaluate item['unique_id'] which is the id + segment id?
        return getProcessById(cb, item['id'], long(item['segment_id']), initial_data=item)

    # TODO: improve error handling
    # TODO: what field should we use as the canonical id? procguid or id?
    def _retrieve_cb_info(self):
        self.info = self.cb._process_events(self.id, self.segment)['process']
        self.full_init = True

    @property
    def start(self):
        return convert_from_solr(self._attribute('start', -1))

    # This will make CbProcesses able to be sorted alongside events, based on
    # the start time of the process
    @property
    def timestamp(self):
        return self.start

    @property
    def hostname(self):
        return self._attribute('hostname', '')

    @property
    def username(self):
        return self._attribute('username', '')

    @property
    def modloads(self):
        i = 0
        for raw_modload in self._attribute('modload_complete', []):
            yield self._parse_modload(i, raw_modload)
            i += 1

    @property
    def unsigned_modloads(self):
        return [m for m in self.modloads if not m.is_signed]

    @property
    def filemods(self):
        i = 0
        for raw_filemod in self._attribute('filemod_complete', []):
            yield self._parse_filemod(i, raw_filemod)
            i += 1

    def find_file_writes(self, filename):
        return [filemod for filemod in self.filemods if filemod.path == filename]

    @property
    def path(self):
        return self._attribute('path', '')

    @property
    def binary(self):
        binary_md5 = self._attribute('process_md5', None)
        if not binary_md5 or binary_md5 == '00000000000000000000000000000000':
            return None
        else:
            return getBinaryByMd5(self.cb, binary_md5)

    @property
    def parent(self):
        parent_unique_id = self._attribute('parent_unique_id', None)
        parent_id = self._attribute('parent_id', None)

        if parent_unique_id:
            return getProcessById(self.cb,
                                  self.get_correct_unique_id(parent_id, parent_unique_id),
                                  1)
        elif parent_id:
            return getProcessById(self.cb, parent_id, 1)
        else:
            return None  # no parent, top of the tree

    @property
    def cmdline(self):
        cmdline = self._attribute('cmdline')
        if not cmdline:
            return self.path
        else:
            return cmdline

    @property
    def children(self):
        i = 0
        for raw_childproc in self._attribute('childproc_complete', []):
            yield self._parse_childproc(i, raw_childproc)
            i += 1

    @property
    def crossprocs(self):
        i = 0
        for raw_crossproc in self._attribute('crossproc_complete', []):
            yield self._parse_crossproc(i, raw_crossproc)
            i += 1

    @property
    def sensor(self):
        # TODO: the CbSensor is currently not cached, so this causes a RTT to the Cb server every time.
        return getSensorById(self.cb, int(self._attribute('sensor_id', 0)))

    @property
    def url(self):
        return '%s/#analyze/%s/%s' % (self.cb.url, self.id, self.segment)

    @property
    def all_events(self):
        return sorted(list(self.modloads) + list(self.netconns) + list(self.filemods) + \
                      list(self.children) + list(self.regmods) + list(self.crossprocs))

    @property
    def tamper_events(self):
        return [e for e in self.all_events if e.tamper_event]

    def get_correct_unique_id(self, old_style_id, new_style_id):
        # this is required for the new 4.2 style GUIDs...
        (sensor_id, proc_pid, proc_createtime) = parse_42_guid(new_style_id)
        if sensor_id != self.sensor.id:
            return old_style_id
        else:
            return new_style_id

    def _parse_crossproc(self, seq, raw_crossproc):
        def _lookup_privilege(privilege_code):
            if privilege_code == 0x1FFFFF:
                return 'PROCESS_ALL_ACCESS'
            elif privilege_code == 0x001F0000L:
                return 'STANDARD_RIGHTS_ALL'
            elif privilege_code == 0x000F0000L:
                return 'STANDARD_RIGHTS_REQUIRED'
            elif privilege_code == 0x00020000L:
                return 'STANDARD_RIGHTS_READ'

            # for the rest, then add "or" for each component.
            components = []
            for element in windows_rights_dict.keys():
                if (privilege_code & element) == element:
                    components.append(windows_rights_dict[element])

            return " | ".join(components)

        parts = raw_crossproc.split('|')
        new_crossproc = {}
        timestamp = datetime.strptime(parts[1], cb_datetime_format)

        # Types currently supported: RemoteThread and ProcessOpen
        new_crossproc['type'] = parts[0]
        new_crossproc['target_procguid'] = parts[2]
        new_crossproc['target_md5'] = parts[3]
        new_crossproc['target_path'] = parts[4]

        # subtype is only valid for ProcessOpen
        if new_crossproc['type'] == 'ProcessOpen' and int(parts[5]) == 2:
            # this is a thread open not a process open
            new_crossproc['type'] = 'ThreadOpen'

        try:
            privilege = int(parts[6])
        except ValueError:
            privilege = 0
        new_crossproc['privileges'] = _lookup_privilege(privilege)
        new_crossproc['privilege_code'] = privilege

        new_crossproc['tamper_flag'] = False
        if parts[7] == 'true':
            new_crossproc['tamper_flag'] = True

        return CbCrossProcEvent(self, timestamp, seq, new_crossproc)

    def _parse_modload(self, seq, raw_modload):
        parts = raw_modload.split('|')
        new_mod = {}
        timestamp = datetime.strptime(parts[0], cb_datetime_format)
        new_mod['md5'] = parts[1]
        new_mod['path'] = parts[2]

        # use the cached data from the parent if possible
        binaries = self._attribute('binaries', None)
        if binaries:
            md5 = new_mod['md5'].upper()
            if md5 in binaries:
                return CbModLoadEvent(self, timestamp, seq, new_mod, binaries[md5])

        return CbModLoadEvent(self, timestamp, seq, new_mod)

    def _parse_filemod(self, seq, filemod):
        def _lookup_type(filemodtype):
            if filemodtype == 1:
                return 'CreatedFile'
            elif filemodtype == 2:
                return 'FirstWrote'
            elif filemodtype == 4:
                return 'Deleted'
            elif filemodtype == 8:
                return 'LastWrote'

        def _lookup_filetype(filetype):
            if filetype == 1:
                return 'PE'
            elif filetype == 2:
                return 'ELF'
            elif filetype == 3:
                return 'MachO'
            elif filetype == 8:
                return 'EICAR'
            elif filetype == 0x10:
                return 'DOC'
            elif filetype == 0x11:
                return 'DOCX'
            elif filetype == 0x30:
                return 'PDF'
            elif filetype == 0x40:
                return 'ZIP'
            elif filetype == 0x41:
                return 'LZH'
            elif filetype == 0x42:
                return 'LZW'
            elif filetype == 0x43:
                return 'RAR'
            elif filetype == 0x44:
                return 'TAR'
            elif filetype == 0x45:
                return '7Z'
            else:
                return 'Unknown'

        if not filemod:
            return

        parts = filemod.split('|')
        new_file = {}
        new_file['type'] = _lookup_type(int(parts[0]))
        timestamp = datetime.strptime(parts[1], cb_datetime_format)
        new_file['path'] = parts[2]
        new_file['md5'] = parts[3]
        new_file['filetype'] = 'Unknown'
        if len(parts) > 4 and parts[4] != '':
            new_file['filetype'] = _lookup_filetype(int(parts[4]))

        new_file['tamper_flag'] = False
        if len(parts) > 5 and parts[5] == 'true':
            new_file['tamper_flag'] = True

        return CbFileModEvent(self, timestamp, seq, new_file)

    def _parse_netconn(self, seq, netconn):
        parts = netconn.split('|')
        new_conn = {}
        timestamp = datetime.strptime(parts[0], cb_datetime_format)
        try:
            new_conn['ipaddr'] = socket.inet_ntop(socket.AF_INET, struct.pack('>i', int(parts[1])))
        except:
            new_conn['ipaddr'] = '0.0.0.0'
        new_conn['port'] = int(parts[2])
        new_conn['protocol'] = protocols[int(parts[3])]
        new_conn['dns'] = parts[4]
        if parts[5] == 'true':
            new_conn['direction'] = 'Outbound'
        else:
            new_conn['direction'] = 'Inbound'

        return CbNetConnEvent(self, timestamp, seq, new_conn)

    @property
    def netconns(self):
        i = 0
        for raw_netconn in self._attribute('netconn_complete', []):
            yield self._parse_netconn(i, raw_netconn)
            i += 1

    @property
    def regmods(self):
        i = 0
        for raw_regmod in self._attribute('regmod_complete', []):
            yield self._parse_regmod(i, raw_regmod)
            i += 1

    def _parse_regmod(self, seq, regmod):
        def _lookup_type(regmodtype):
            if regmodtype == 1:
                return 'CreatedKey'
            elif regmodtype == 2:
                return 'FirstWrote'
            elif regmodtype == 4:
                return 'DeletedKey'
            elif regmodtype == 8:
                return 'DeletedValue'

        parts = regmod.split('|')
        new_regmod = {}
        timestamp = datetime.strptime(parts[1], cb_datetime_format)
        new_regmod['type'] = _lookup_type(int(parts[0]))
        new_regmod['path'] = parts[2]

        new_regmod['tamper_flag'] = False
        if len(parts) > 3 and parts[3] == 'true':
            new_regmod['tamper_flag'] = True

        return CbRegModEvent(self, timestamp, seq, new_regmod)

    def _parse_childproc(self, seq, childproc):
        parts = childproc.split('|')
        timestamp = datetime.strptime(parts[0], cb_datetime_format)
        new_childproc = {}
        new_childproc['procguid'] = parts[1]
        new_childproc['md5'] = parts[2]
        new_childproc['path'] = parts[3]
        new_childproc['pid'] = parts[4]

        # TODO: better handling of process start/terminate
        new_childproc['terminated'] = False
        if parts[5] == 'true':
            new_childproc['terminated'] = True

        new_childproc['tamper_flag'] = False
        if len(parts) > 6 and parts[6] == 'true':
            new_childproc['tamper_flag'] = True

        return CbChildProcEvent(self, timestamp, seq, new_childproc)

    @property
    def last_update(self):
        return convert_from_solr(self._attribute('last_update', -1))


@lrumemoized
def getBinaryByMd5(cb, md5sum, initial_data=None):
    return CbBinary(cb, md5sum, initial_data)

@lrumemoized
def getProcessById(cb, procid, segment, initial_data=None):
    return CbProcess(cb, procid, segment, initial_data)

@lrumemoized
def getSensorById(cb, sensor_id, initial_data=None):
    return CbSensor(cb, sensor_id, initial_data)


class MultiCbApi2(object):
    def __init__(self, server_json_dict=None, debug=False):
        self.cbservers = {}
        self.debug = debug

        # logging
        self._logger = logging.getLogger('co.redcanary.cbapi2')

        if server_json_dict:
            for server in server_json_dict:
                self.addCbServer(server)

    def addCbServer(self, server_info):
        if not server_info.has_key('name'):
            raise Exception("No shortname in dictionary ('name')")

        shortname = server_info['name']

        if not server_info.has_key('cb_url'):
            raise Exception("No url for shortname %s" % shortname)
        if not server_info.has_key('cb_api_token'):
            raise Exception("No API token for shortname %s")

        proxy = server_info.get('proxy', None)

        c = CbApi2(server_info.get('cb_url'), server_info.get('cb_api_token'),
                   ssl_verify=False, debug=self.debug, proxy=proxy)
        self.cbservers[shortname] = c

    def binary_search(self, query_string=u'', sort_string=None):
        for shortname in self.cbservers:
            try:
                query = self.cbservers[shortname].binary_search(query_string)
                if sort_string:
                    query.sort(sort_string)
                for binary in query:
                    yield (shortname, binary)
            except Exception, e:
                self._logger.error("Error grabbing binaries from server %s: %s" % (shortname, e.message))

    def process_search(self, query_string=u'', sort_string=None):
        for shortname in self.cbservers:
            try:
                query = self.cbservers[shortname].process_search(query_string)
                if sort_string:
                    query.sort(sort_string)
                for proc in query:
                    yield (shortname, proc)
            except Exception, e:
                self._logger.error("Error grabbing processes from server %s: %s" % (shortname, e.message))


class CbApi2(object):
    def __init__(self, url, api_token, ssl_verify=True, retry_count=5, debug=False, proxy=None):

        if not url.startswith(('http://', 'https://')):
            raise Exception("Malformed URL")

        self.url = url.rstrip('/')
        self._parsed_url = urlparse.urlparse(self.url)
        self._ssl_verify = ssl_verify
        self._default_args = {"cb.urlver": 1, 'facet': ['false', 'false']}
        self._retry_count = retry_count

        if debug:
            # only enable logging once
            self._enable_logging()

        # set up requests header
        self._token_header = {'X-Auth-Token': api_token}

        # logging
        self._logger = logging.getLogger('co.redcanary.cbapi2')

        # quirks
        self._unicode_quirk = True

        if proxy:
            self._proxy = {'http': proxy, 'https': proxy}
        else:
            self._proxy = None

        # set up Quirks mode
        # get server version
        r = self._do_request('/api/info')
        server_info = r.json()
        self._logger.debug('Connected to Cb server version %s at %s' % (server_info['version'],
                                                                       self.url))
        self.cb_server_version = LooseVersion(server_info['version'])
        if self.cb_server_version >= LooseVersion('4.2'):
            # disable Unicode quirk
            self._unicode_quirk = False
        if self.cb_server_version < LooseVersion('4.1'):
            raise Exception("CbApi2 only supports Cb servers version >= 4.1")

        self._handle_quirks()

    @staticmethod
    def _enable_logging():
        l = logging.getLogger('co.redcanary.cbapi2')
        l.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        l.addHandler(ch)

    def _handle_quirks(self):
        if self._unicode_quirk:
            self._logger.debug('Enabling unicode quirk')

            def construct_yaml_str(self, node):
                try:
                    rawdata = b''.join([chr(ord(x)) for x in self.construct_scalar(node)])
                    return rawdata.decode('utf8')
                except ValueError:
                    # apparently sometimes the data is already correctly encoded
                    return self.construct_scalar(node)

            Loader.add_constructor(u'tag:yaml.org,2002:str', construct_yaml_str)
            SafeLoader.add_constructor(u'tag:yaml.org,2002:str', construct_yaml_str)

    def _decode_json(self, response):
        if self._unicode_quirk:
            return yaml.load(response.content)
        else:
            return cjson.decode(response.content, all_unicode=True)

    def _do_request(self, urlobject, query_parameters=None, data=None):
        url = '%s%s' % (self.url, urlobject)
        if query_parameters:
            url += '?%s' % (urllib.urlencode(query_parameters))

        keep_retrying = True
        retry_count = 0
        retry_delay = 5  # default to 5 seconds with exponential backoff

        timeout = 120    # default 2 minute timeout (nginx on the cb side will timeout after 60 seconds)

        while keep_retrying:
            if data:
                r = requests.post(url, data=data, headers=self._token_header, verify=self._ssl_verify,
                                  proxies=self._proxy, timeout=timeout)
                self._logger.debug('HTTP POST {0:s} took {2:.3f}s (response {1:d})'.format(url, r.status_code,
                                                                                           r.elapsed.total_seconds()))
            else:
                r = requests.get(url, data=data, headers=self._token_header, verify=self._ssl_verify,
                                 proxies=self._proxy, timeout=timeout)
                self._logger.debug('HTTP GET {0:s} took {2:.3f}s (response {1:d})'.format(url, r.status_code,
                                                                                          r.elapsed.total_seconds()))

            if r.status_code == 200:
                return r
            elif r.status_code == 504 or r.status_code == 502:   # gateway timeout or bad gateway respectively
                if retry_count == self._retry_count:
                    keep_retrying = False
                else:
                    # try to retry the query
                    retry_count += 1
                    self._logger.warning(
                        'Query {0:s} failed - retry {1:d} - sleeping {2:d} seconds'.format(url, retry_count,
                                                                                           retry_delay))
                    time.sleep(retry_delay)
                    retry_delay *= 2
            else:
                break

        raise CbAPIError(r)


    # Select binary or process by unique ID
    def select_binary(self, md5):
        return getBinaryByMd5(self, md5, initial_data=None)

    def select_process(self, procid, segment=1):
        return getProcessById(self, procid, int(segment), initial_data=None)

    def select_sensor(self, sensor_id):
        result = self._do_request(u'/api/v1/sensor/{0:d}'.format(sensor_id))

        initial_data = self._decode_json(result)
        if initial_data:
            return getSensorById(self, int(sensor_id), initial_data=initial_data)
        else:
            return None

    ### LOW LEVEL ACCESS ###
    def _process_events(self, procid, segment=1):
        if type(procid) == int or type(procid) == long:
            r = self._do_request('/api/v1/process/{0:d}/{1:d}/event'.format(procid, segment))
        else:
            r = self._do_request('/api/v1/process/{0:s}/{1:d}/event'.format(procid, segment))

        # TODO: too low-level. Do we need to split these queries into a separate class?
        return self._decode_json(r)

    def _binary_summary(self, md5):
        r = self._do_request(u'/api/v1/binary/{0:s}/summary'.format(md5.upper()))

        return self._decode_json(r)

    def _get_binary(self, md5sum):
        r = self._do_request(u'/api/v1/binary/{0:s}'.format(md5sum.upper()))

        # TODO: too low-level. Do we need to split these queries into a separate class?
        return r.content

    def _binary_frequency(self, md5sum):
        r = self._do_request(u'/api/v1/process/host/count',
                             query_parameters={'cb.freqver': 1, 'name': 'md5', 'md5': md5sum})

        return self._decode_json(r)

    def _sensor_info(self, id):
        r = self._do_request(u'/api/v1/sensor/{0:d}'.format(id))

        return self._decode_json(r)

    ### LOW LEVEL ACCESS ###

    def _count(self, urlobject, query_string=None):
        args = self._default_args
        args['start'] = 0
        args['rows'] = 0

        if query_string:
            args['q'] = query_string

        r = self._do_request(urlobject, args)

        result = self._decode_json(r)
        return result.get('total_results')

    # searches
    def binary_search(self, query_string=u'', start=0):
        if type(query_string) == unicode:
            query_string = query_string.encode('utf-8')

        ds = CbDocumentQuery(query_string, CbBinary, self)
        return ds

    def process_search(self, query_string=u'', start=0):
        if type(query_string) == unicode:
            query_string = query_string.encode('utf-8')

        ds = CbDocumentQuery(query_string, CbProcess, self)
        return ds

    def sensor_search(self, hostname='', ipaddr=''):
        if not hostname and not ipaddr:
            query = None
        elif hostname and not ipaddr:
            query = {'hostname': hostname}
        else:
            query = {'ip': ipaddr}

        result = self._do_request('/api/v1/sensor', query_parameters=query)

        for item in self._decode_json(result):
            yield getSensorById(self, long(item['id']), initial_data=item)

    def from_ui(self, uri):
        o = urlparse.urlparse(uri)
        if self._parsed_url.scheme != o.scheme or \
                        self._parsed_url.hostname != o.hostname or \
                        self._parsed_url.port != o.port:
            raise Exception("Invalid URL provided")

        if o.fragment.startswith('analyze'):
            (analyze, procid, segment) = o.fragment.split('/')[:3]
            return self.select_process(procid, int(segment))
        elif o.fragment.startswith('binary'):
            (binary, md5) = o.fragment.split('/')[:2]
            return self.select_binary(md5)
        elif o.fragment.startswith('login') or not o.fragment:
            return self
        else:
            raise Exception("Unknown URL endpoint: %s" % o.path)

    def get_installer(self, sensor_type=None, os_type='windows', sensor_group_id=1):
        if self.cb_server_version < LooseVersion('4.1.4'):
            raise Exception("Cannot get installer for Cb versions < 4.1.4")

        if os_type != 'windows' and self.cb_server_version < LooseVersion('4.2.1'):
            raise Exception("Cb versions < 4.2.1 only support Windows")

        if sensor_type:
            result = self._do_request('/api/v1/group/{0:d}/installer/{1:s}/{2:s}'.format(sensor_group_id,
                                                                                     os_type,
                                                                                     sensor_type))
        else:
            result = self._do_request('/api/v1/group/{0:d}/installer/{1:s}'.format(sensor_group_id,
                                                                                     os_type))

        return result.content

    def get_license_status(self):
        result = self._do_request('/api/v1/license')
        return result.json()

    def update_license(self, new_license_block):
        try:
            result = self._do_request('/api/v1/license', data=cjson.encode({'license': new_license_block}))
        except CbAPIError:
            return False

        if result.json()['result'] == 'success':
            return True
        else:
            return False


def from_ui(uri, apitoken, ssl_verify=True, retry_count=5):
    parsed_url = urlparse.urlparse(uri)
    root_url = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))

    cb = CbApi2(root_url, apitoken, ssl_verify, retry_count)
    return cb.from_ui(uri)


def write_event_csv(all_events, fp, header_row=True):
    eventwriter = csv.writer(fp)
    
    if header_row == True:
        eventwriter.writerow(['ProcessPath', 'Timestamp', 'Event', 'Path/IP/Domain', 'Comments'])

    for event in all_events:
        if type(event) == CbFileModEvent:
            eventwriter.writerow([event.parent.path, event.timestamp, event.type, event.path, ''])
        elif type(event) == CbNetConnEvent:
            if event.dns:
                hostname = event.dns
            else:
                hostname = event.ipaddr
            hostname += ':%d' % event.port

            eventwriter.writerow([event.parent.path, event.timestamp, event.direction + ' netconn', hostname, ''])
        elif type(event) == CbRegModEvent:
            eventwriter.writerow([event.parent.path, event.timestamp, event.type, event.path, ''])
        elif type(event) == CbChildProcEvent:
            eventwriter.writerow([event.parent.path, event.timestamp, 'childproc', event.path, event.proc.cmdline])
        elif type(event) == CbModLoadEvent:
            eventwriter.writerow([event.parent.path, event.timestamp, 'modload', event.path, event.md5])

    return 0


def get_api_token(hostname, username, password):
    r = requests.get('http://%s/api/auth' % hostname,
                     auth=requests.auth.HTTPDigestAuth(username,
                     password)).json()
    return r['auth_token']

