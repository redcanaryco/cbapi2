try:
    __version__ = __import__('pkg_resources').get_distribution(__name__).version
except Exception, e:
    __version__ = 'unknown'

# Public API

from cbapi2 import MultiCbApi2, CbApi2, from_ui
from cbapi2 import CbChildProcEvent, CbNetConnEvent, CbRegModEvent, CbFileModEvent, CbModLoadEvent, CbCrossProcEvent
from cbapi2 import CbProcess, CbSensor, CbBinary
from cbapi2 import write_event_csv

