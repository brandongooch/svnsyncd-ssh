# svnsyncd

Subversion Repository Synchronization Daemon

## NOTES:

In the 'sync_the_repository' method, we may need to handle these errors
in a special way (other than the default of returning an generic error):

  E000022:
  Revision being currently copied (1386), last merged revision (1385),
  and destination HEAD (1387) are inconsistent; have you committed
  to the destination without using svnsync?

  E160024:
  Conflict at '/trunk/path/to/file'

  E160028:
  '/trunk/path/to/file' is out of date

  E200014:
  Base checksum mismatch on '/trunk/Maverick/services/AIMIntegrationService/.classpath':
  expected:  2fc2793fd58f85c3e062ac6551975321 actual:  3e4b5656d196f5150afd4e7e9b15efa5

  E160049:
  revprop 'svn:date' has unexpected value in filesystem

  E160020:
  File already exists: filesystem '/data/repositories/synctest9/db', transaction '587-gj', path '/trunk/to/file/ad'

## LICENCE:

Copyright (c) 2014 James Brandon Gooch

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
