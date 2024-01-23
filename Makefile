# Copyright (c) 2014 James Brandon Gooch
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.

PROGNAME=svnsyncd
DESTDIR?=/data
SBINDIR=${DESTDIR}/sbin
ETCDIR=${DESTDIR}/etc
INITDIR=/etc/init.d
LOGROTATEDIR=/etc/logrotate.d

install:
	install -o root -g root -m 0755 src/${PROGNAME}.py ${SBINDIR}/${PROGNAME}
	install -o root -g root -m 0644 src/${PROGNAME}.conf.sample ${ETCDIR}
	install -o root -g root -m 0755 src/etc/init.d/${PROGNAME} ${INITDIR}
	install -o root -g root -m 0755 src/etc/logrotate.d/${PROGNAME} ${LOGROTATEDIR}
ifeq ($(wildcard ${DESTDIR}/var/db/svnsyncd.db),)
	mkdir -p ${DESTDIR}/var/db
	touch ${DESTDIR}/var/db/svnsyncd.db
endif

uninstall:
	rm -f ${SBINDIR}/${PROGNAME}
	rm -f ${ETCDIR}/${PROGNAME}.conf.sample
	rm -f ${INITDIR}/${PROGNAME}
	rm -f ${LOGROTATEDIR}/${PROGNAME}
