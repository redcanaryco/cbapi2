# Carbon Black Enterprise API

This is a Pythonic API to access Cb servers through the [RESTful API defined at the Carbon Black
GitHub repository](https://github.com/carbonblack/cbapi/).

This API was built at [Red Canary](https://redcanary.co/) in order to make exploring the Carbon Black datastore
easy and intuitive. There are two major design goals behind this API implementation: first, make the API
"feel" more like idiomatic Python. The ultimate goal is to make working with Cb data close to working with
Python objects. Second, reduce the requests made to the server to the bare minimum required-see 
the Performance section at the end.

## Requirements

The only requirements are Python 2.7+, the Requests module, and PyYAML.

PyYAML should be built with native libyaml support for maximum performance. This means you will probably
want to install the `libyaml-devel` (or appropriately named package for your Unix distribution of choice)
package before attempting to install CbApi2.

## Example scripts

See the `examples/` directory for more examples. For now I don't have good documentation; pull requests welcome!
Here are some snippets of code to help get you started.

### Set up the API and perform a query

    from cbapi2 import CbApi2

    # connect to the Cb API
    c = CbApi2('http://cbserver.local./', 'API_KEY', ssl_verify=False)

Optionally you can add `debug=True` to the CbApi2 keyword arguments in order to get debugging information
from the CbApi2 library.

Once you receive a CbApi2 object, here are the major methods you can call in order to perform
queries on the Cb server:

* `from_ui` : takes a full URL from the UI (for example, https://cbserver.local./#analyze/00000002-0000-06d4-01d0-6d9e91c17eee/1)
  and returns an appropriate (process, binary, or sensor) object representing the data behind that URL.
* `process_search` : prepares a process search query
* `binary_search` : prepares a binary search query
* `select_binary` : select a binary by MD5sum
* `select_process` : select a process by Cb process ID

For example, to find all notepad processes with at least one filemod, sorting by number of filemods descending:

    query = c.process_search('process_name:notepad.exe filemod_count:[1 TO *]').sort('filemod_count desc')

The `process_search` method will not execute the query until you attempt to retrieve the results, either by
iterating over the returned query object or using the array slice notation to retrieve a subset of results.
Similarly, using Python's built-in `len()` operator on the query object will retrieve the number of documents
matched by the query.

### Iterate over all file modifications for the processes matched by the query

    for proc in query:
        # display all filemods for this process
        print 'filemods:'
        for ml in proc.filemods:
            print ' ', ml.path

Once you have a process document, you can access any of the JSON fields by simply accessing the name as if
it were a property of the object. For example, you can get the start time of the process above by calling
`proc.start`. CbApi2 attempts to convert the result into a usable Python datatype whenever possible, so
the start time will be returned not as a string but as a Python `datetime` type.

You can always retrieve the original document that backs a document object by calling `proc.original_document`.
The parent process is accessed through the `parent` property (eg. `proc.parent` - which of course can be
nested as long as there are more parents in the tree - `proc.parent.parent.parent`). The same can be done with
the children of a process - the `proc.children` method is enumerable and returns all child processes of the
current process.

### Get binary data for the process

    if proc.binary.signed:
        print 'Process binary was signed; signing data was:', proc.binary.signing_data
    else:
        print 'Process binary was not signed:', proc.binary.signing_data

    print proc.binary.frequency  # print how frequent that binary shows up in the datastore

Note that you can get the binary document for a process by calling through the `binary` method. This will
return a full binary document object through which you can query any of the binary metadata. You can also
call `file` on the binary object to obtain a file-like stream object containing the original uploaded
binary file.

### Request all events for the process

    all_events = proc.all_events

You can merge events from multiple processes into one list and then sort by timestamp by calling the built-in
Python `sorted()` function.

### Return only the first ten results of a query

    query = c.process_search()   # Get all processes
    first_10_procs = query[:10]

### Get the original process document for a process

    proc.original_document

## Performance & Caching

A major design goal for CbApi2 was to provide a high-performance way to access a Cb server with a minimum of fuss.
To accomplish this goal, there are three major performance optimizations that are implemented. The first, lazy
querying, is covered above- no query is performed until the code attempts to enumerate the result set.

Second, in order to minimize RTTs to the Cb server and maximize performance, CbApi2 caches document results for a 
maximum of 1 minute. If you attempt to re-retrieve the same process document within a minute of the last time
it was accessed, then CbApi2 will return the cached version of the document.

Third, the underlying Cb API returns some metadata about search results as part of the search query itself.
For example, as of Cb server 5.0, the `path`, `process_name`, `process_md5`, and `parent_name` fields (among others)
for each search result are all returned as part of the search results themselves- not requiring another RTT to
get the process document itself. CbApi2 will not retrieve the full process document until absolutely necessary.

## Known Issues

* Sensor document objects work *almost* but not quite the same as binary and process documents. Notably, `sensor_search`
  will not return a query object but rather directly yields the results back to the caller.
* More documentation!
* Many more yet to be discovered, no doubt. Pull requests and issues welcome.
