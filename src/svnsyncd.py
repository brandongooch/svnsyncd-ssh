#!/usr/bin/env python

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

from atexit import register
import glob
import errno
import logging
import optparse
import os
import pty
from re import *
import subprocess
from subprocess import *
from sys import *
from ConfigParser import ConfigParser
from logging import handlers
from Queue import Queue
from random import *
from signal import *
from threading import *
from time import sleep, time

# Global counter
DEBUG_COUNTER = 0

# Lock debugging output
DEBUG_THREAD = False

# Lock debugging output
DEBUG_LOCK = True

# Daemon configuration dictionary
CONFIG = {}

# The Signals
SIGNAL_TERM = False
SIGNAL_USR1 = False

# Internal Stuff
POLLINTERVAL = 15

# Reposistory Dictionary and Lock
# This dictionary will have a record for each repository that is being sync'ed.
# Also, create a Lock to protect it.
REPOS = {}
REPOS_MTX = Lock()

# List of svnsync threads
SYNCTHREADS = []
SYNCTHREADS_MTX = Lock()

# Global Log Settings
# See: http://docs.python.org/library/logging.handlers.html
LOG_FILENAME = '/var/log/svnsyncd.log'
LOGGER = logging.getLogger('svnsyncd')
LOGFILE = logging.handlers.WatchedFileHandler(LOG_FILENAME)
formatter = logging.Formatter('%(asctime)s %(msg)s',
    datefmt='%m-%d-%Y %I:%M:%S%p')
LOGFILE.setFormatter(formatter)
LOGGER.addHandler(LOGFILE)

# I set the logging module log level to LOG_INFO ALWAYS -- it's a hack
# The logging module in python seems to be tailored for debug logging,
# not necessarily application information run-time logging.
# However, I want to use it for that, so I just need to create
# a log level and log message processing convention -- an abstraction.
# See the next lines for implementation details...
LOGGER.setLevel(logging.INFO)

# Actual log level, set in the configuration file
LOG_LEVEL = 4

# ...and log level types
LOG_CRITICAL    = 1
LOG_ERROR       = 2
LOG_WARNING     = 3
LOG_INFO        = 4
LOG_DEBUG       = 5

# Are we a daemon?
DAEMONIZED = True

def logentry(msg, level):
    '''Creates a log entry. See Global Log Settings for details'''

    if level == None:
        level = LOG_ERROR
    if level <= LOG_LEVEL:
        # If we're running in the foreground,
        # write the log messages to the terminal.
        if not DAEMONIZED:
            print '%s' % (msg)
        # Write the message to the log
        LOGGER.info(msg)

def configure_svnsyncd(configfile):
    '''Reads the configuration details for the svnsyncd daemon'''

    # Log level
    global LOG_LEVEL

    # By default, return 0 for error_flag and a None object for msg
    msg = ''
    error_flag = 0

    option_names = [
        'configfile',
        'svnsyncdb',
        'svn_bin_path',
        'bin_svn',
        'bin_svnadmin',
        'bin_svnlook',
        'bin_svnsync',
        'bin_scp',
        'scpkey',
        'scpuser',
        'syncuser',
        'repositories',
        'pidfile',
        'retry',
        'retrywait',
        'numthreads',
    ]

    config = {
        'configfile'   : '/usr/local/etc/svnsyncd.conf',
        'svnsyncdb'    : '/var/db/svnsyncd.db',
        'svn_bin_path' : '/usr/local/bin',
        'bin_svn'      : '/usr/local/bin/svn',
        'bin_svnadmin' : '/usr/local/bin/svnadmin',
        'bin_svnlook'  : '/usr/local/bin/svnlook',
        'bin_svnsync'  : '/usr/local/bin/svnsync',
        'bin_scp'      : '/usr/bin/scp',
        'scpkey'       : '/root/.ssh/id_rsa',
        'scpuser'      : 'root',
        'syncuser'     : 'syncuser',
        'repositories' : '/var/svn',
        'pidfile'      : '/var/run/svnsyncd.pid',
        'retry'        : '1',
        'retrywait'    : '10',
        'numthreads'   : '8',
    }

    # Create a configuration parser
    parser = ConfigParser(defaults = config)
    defaults = parser.defaults()

    try:
        parser.readfp(open(configfile))
    except IOError, error:
        error_flag = True
        msg += 'error: could not read config file: %s\n' % (configfile)
        return None

    # OK, so the configuration file seems legit, so let's go ahead and set it
    config['configfile'] = configfile

    # What is the section heading of the configuration file
    # from which we will retrieve our settings?
    section = 'svnsyncd'

    # What is the path to the replica database?
    try:
        config['svnsyncdb'] = parser.get(section, 'svnsyncdb')
    except:
        error_flag = True
        msg += 'error: svnsyncdb not set in %s\n' % (configfile)

    if not os.path.exists(config['svnsyncdb']):
        error_flag = True
        msg += 'error: replica database file cannot be found: %s\n' \
            % (config['svnsyncdb'])

    # What is the path to the Subversion binaries?
    try:
        config['svn_bin_path'] = parser.get(section, 'svn_bin_path')
    except:
        error_flag = True
        msg += 'error: svn_bin_path not set in %s\n' % (configfile)

    # Set the Subversion binary vars, insuring that the binaries exist
    config['bin_svn']      = '%s/svn'      % (config['svn_bin_path'])
    config['bin_svnadmin'] = '%s/svnadmin' % (config['svn_bin_path'])
    config['bin_svnlook']  = '%s/svnlook'  % (config['svn_bin_path'])
    config['bin_svnsync']  = '%s/svnsync'  % (config['svn_bin_path'])

    if not os.path.exists(config['bin_svn']):
        error_flag = True
        msg += 'error: %s cannot be found\n' % (config['bin_svn'])

    if not os.path.exists(config['bin_svnadmin']):
        error_flag = True
        msg += 'error: %s cannot be found\n' % (config['bin_svnadmin'])

    if not os.path.exists(config['bin_svnlook']):
        error_flag = True
        msg += 'error: %s cannot be found\n' % (config['bin_svnlook'])

    if not os.path.exists(config['bin_svnsync']):
        error_flag = True
        msg += 'error: %s cannot be found\n' % (config['bin_svnsync'])

    # Determine the syncuser from the configuration file
    try:
        config['syncuser'] = parser.get(section, 'syncuser')
    except:
        error_flag = True
        msg += 'error: syncuser not set in %s\n' % (configfile)

    # Determine the repository parent filesystem path
    try:
        config['repositories'] = parser.get(section, 'repositories')
    except:
        error_flag = True
        msg += 'error: repositories not set in %s\n' % (configfile)

    # Validate the repository parent path. Well, at least check to see
    # if it exists. If it doesn't, bail out for now.
    if not os.path.isdir(config['repositories']):
        error_flag = True
        msg += 'error: repositories is invalid: %s\n' \
            % (config['repositories'])

    # Determine the number of retries file from the configuration file
    try:
        config['retry'] =  parser.getint(section, 'retry')
    except:
        error_flag = True
        msg += 'error: retry not set in %s\n' % (configfile)

    # Determine the number of retries file from the configuration file
    try:
        config['retrywait'] = parser.getint(section, 'retrywait')
    except:
        error_flag = True
        msg += 'error: retrywait not set in %s\n' % (configfile)

    # Determine the number threads from the configuration file
    try:
        config['numthreads'] = parser.getint(section, 'numthreads')
    except:
        error_flag = True
        msg += 'error: numthreads not set in %s\n' % (configfile)

    # Determine the log level from the configuration file
    try:
        config['loglevel'] = parser.getint(section, 'loglevel')
        # Set the LOG_LEVEL based on the config value
        LOG_LEVEL = int(config['loglevel'])
    except:
        error_flag = True
        msg += 'error: loglevel not set in %s\n' % (configfile)

    if error_flag:
        logentry(msg, LOG_ERROR)
        config = None

    return (config)


class TimeCommander(object):
    def __init__(self, oscmd):
        self.oscmd  = oscmd
        self.proc   = None
        self.stdout = ''
        self.stderr = ''

    def run(self, timeout):
        logentry('debug: TimeCommander.run: %s' % (self.oscmd), LOG_DEBUG)
        def target():
            self.proc = subprocess.Popen( \
                self.oscmd, \
                stdout=subprocess.PIPE, \
                stderr=subprocess.PIPE, \
                shell=True)
            self.stdout, self.stderr = self.proc.communicate()

        thread = Thread(target = target)
        thread.start()

        thread.join(timeout)

        if thread.is_alive():
            self.proc.terminate()
            thread.join()

        return (self.stdout, self.stderr, self.proc.returncode)


class SVNSyncDBThread(Thread):
    '''The Class that maintains the repository replica dictionary'''
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        '''Default method run of the SVNSyncDBThread Class'''
        self.getrepos_dataset()

    def is_url(self, url):
        '''Determines if url is a valid URL using regular expression'''

        # URL RegEx pattern
        regex_url  = '(svn)?(svn\+ssh)?(http)?(https)?://' \
                     '(?:[a-zA-Z]|[0-9]|[-_@.&+]|[!*\(\),]|' \
                     '(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        if (compile(regex_url).match(url)):
            return True
        else:
            return False

    def is_repo(self, path):
        '''Determines if path is a Subversion repository'''

        # If path isn't a directory, it's also not a Subversion repo.
        if not os.path.isdir(path):
            return False

        # If the `svnlook uuid` command successfully completes,
        # then it turns out that we do indeed have a repository.
        oscmd = '%s uuid %s' % (CONFIG['bin_svnlook'], path)
        command = TimeCommander(oscmd)

        logentry('debug: SVNSyncDBThread.is_repo: %s' % (oscmd), LOG_DEBUG)

        try:
            (stdout, stderr, error) = command.run(timeout = 300)
            if (error != 0):
                return False
            else:
                return True
        except:
            logentry('error: call failed: %s' % (oscmd), LOG_ERROR)

        return False

    def verify_replica_src(self, path, src):
        '''Determines if src is legit'''

        # Take a peek at the replica source.
        oscmd = '%s propget %s ' % (CONFIG['bin_svnlook'], path)
        oscmd += '--revprop -r0 svn:sync-from-url'
        command = TimeCommander(oscmd)

        logentry('debug: SVNSyncDBThread.verify_replica_src: ' \
            '%s' % (oscmd), LOG_DEBUG)

        try:
            (stdout, stderr, error) = command.run(timeout = 300)
            if (error != 0):
                logentry('error: %s: get_replica_url: %s' \
                    % (path, stderr), LOG_ERROR)
                return False
            if self.is_url(stdout):
                if stdout == src:
                    return True
            else:
                return False
        except:
            logentry('error: Popen failed: %s' % (oscmd), LOG_ERROR)
            return False

    def get_replica_record(self, line, lineno):
        '''Obtain a replica record from the db file'''

        # Grab the record and split it up on whitespace.
        rec = line.strip().split()

        if len(rec) >= 1:
            # If the record has at least one field, let's try to read it.
            # If the line begins with a #, it is a comment.
            regex_comment = '^#'
            if (compile(regex_comment).match(rec[0])):
                return None
        else:
            return None

        # If the record contains at least one field and that field is not
        # a comment, make sure the record does have the correct number of
        # fields that make a complete record.
        if not len(rec) == 2:
            msg  = 'error: get_replica_record: %s: ' % (CONFIG['svnsyncdb'])
            msg += 'invalid replica record, line %d' % (int(lineno))
            logentry(msg, LOG_ERROR)
            return None

        # Apparently, we have a correctly formatted record. Now we need to
        # vefify the information it contains.
        name = rec[0]
        src  = rec[1]
        path = '%s/%s' % (CONFIG['repositories'], name)

        if not DEBUG_THREAD:
            # Verify the repository.
            if not self.is_repo(path):
                logentry('error: get_replica_record: %s is not a repository'
                    % (path), LOG_ERROR)
                return None
    
            # Verify the source URL.
            # Ensure that the source URL matches the svn:sync-from-url
            # property set in the repository.
            if not self.verify_replica_src(path, src):
                msg  = 'error: get_replica_record: '
                msg += '%s is not the replica source for %s, ' % (src, path)
                msg += 'line %d' % (int(lineno))
                logentry(msg, LOG_ERROR)
                return None

        # The record seems legit, now let's construct the dictionary
        # to return to the caller...
        record = {}
        record['name'] = name
        record['path'] = path
        record['src']  = src

        # ...then return it.
        return record

    def get_repos_dataset(self):
        '''Populate the global repository dataset'''

        # Access the global configuration dictionary
        global CONFIG

        # Access the global repository dataset
        global REPOS

        logentry('debug: SVNSyncDBThread.get_repos_dataset: ' \
            'reading repository replica database', LOG_DEBUG)

        if DEBUG_LOCK:
            logentry('debug: SVNSyncDBThread.get_repos_dataset: acquiring %s' \
                % (REPOS_MTX), LOG_DEBUG)

        # Grab the REPOS Lock.
        REPOS_MTX.acquire()

        # Clear the REPOS dataset.
        REPOS.clear()

        try:
            with open(CONFIG['svnsyncdb']) as fd:
                lineno = 0
                for line in fd:
                    lineno = lineno + 1
                    record = self.get_replica_record(line, lineno)
                    if not record == None:
                        msg  = 'debug: SVNSyncDBThread.get_repos_dataset: '
                        msg += 'record: %s' % (record)
                        logentry(msg, LOG_DEBUG)
                        name = record['name']
                        path = record['path']
                        src = record['src']
                        dst = 'file://%s' % (path)
                        if name not in REPOS:
                            REPOS[name] = {}
                            REPOS[name]['name']      = name
                            REPOS[name]['path']      = path
                            REPOS[name]['src']       = src
                            REPOS[name]['dst']       = dst
                            REPOS[name]['syncing']   = False
                            REPOS[name]['syncerror'] = False
                            REPOS[name]['gone']      = False
                            REPOS[name]['mtx']       = Lock()
                        else:
                            msg  = 'debug: SVNSyncDBThread.get_repos_dataset: '
                            msg += 'record exists for %s' % (REPOS[name])
                            logentry(msg, LOG_DEBUG)
        except:
            msg  = 'error: get_repos_dataset: '
            msg += 'could not open %s' % (CONFIG['svnsyncdb'])
            logentry(msg, LOG_DEBUG)

        if len(REPOS) == 0:
            msg  = 'info: no replicas configured '
            msg += 'for synchronization in %s' % (CONFIG['svnsyncdb'])
            logentry(msg, LOG_INFO)
            

        # Release the REPOS Lock.
        if DEBUG_LOCK:
            logentry('debug: SVNSyncDBThread.get_repos_dataset: releasing %s' \
                % (REPOS_MTX), LOG_DEBUG)

        REPOS_MTX.release()


class SyncDaemon():
    '''The main Class for svnsyncd daemon'''
    def __init__(self):

        # Daemon specifics
        self.pidfile           = '/var/run/svnsyncd.pid'
        self.stdin             = '/dev/null'
        self.stdout            = '/dev/null'
        self.stderr            = '/dev/null'

    def signal_handler(self, signum, frame):
        '''Handle signals thrown at the daemon

        Currently:

        SIGTERM: Terminates the application
        SIGUSR1: Causes the daemon to reread the configuration file,
                 renitialize the run-time data structures, and rotate
                 the LOGFILE
        '''

        # The Signals
        global SIGNAL_TERM
        global SIGNAL_USR1

        if signum == SIGTERM:
            if not SIGNAL_TERM:
                logentry('info: SIGTERM received, shutting down...', LOG_INFO)
                SIGNAL_TERM = True
                # Call a stop to the madness
                self.stop()

        elif signum == SIGUSR1:
            if not SIGNAL_USR1:
                logentry('info: reinitializing replica dataset', LOG_INFO)
                SIGNAL_USR1 = True
                # Wait for the svnsync processes to finish
                for t in SYNCTHREADS:
                    t.join()
                # Fill the REPOS dictionary
                reposdatasetthread = SVNSyncDBThread()
                reposdatasetthread.start()
                reposdatasetthread.join()
                SIGNAL_USR1 = False

    def getpidfrompidfile(self):
        '''Reads the PID from the PID file'''
        pid = -1
        try:
            pf = file(self.pidfile,'r')
            try:
                pid = int(pf.read().strip())
            except:
                msg = 'error: could not retrieve pid from pidfile %s\n'
                stderr.write(msg % self.pidfile)
                exit(1)
            pf.close()
        except IOError:
            pid = None
        return pid

    def double_fork_it(self):
        '''Implements the so-called 'UNIX Double-Fork Magic'

        The technique has been implemented as described by the late,
        great Richard W. Stevens in the seminal UNIX programming classic:

            "Advanced Programming in the UNIX Environment" (ISBN 0201563177)

        Also, I copied and pasted this from amother piece of code that I
        found somewhere, sometime ago. Proper attribution? I'll be working
        on that...
        '''

        # Let's try to write the pid file, and bail if we can't
        try:
            file(self.pidfile, 'w+').write('')
        except:
            stderr.write('error: could not write pidfile %s\n' \
                % self.pidfile)
            exit(1)

        # Perform the first fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                exit(0)
        except OSError, e:
            stderr.write('error: first fork failed: %d (%s)\n' % \
                (e.errno, e.strerror))
            exit(1)

        # Decouple from parent environment
        os.chdir('/')
        os.setsid()
        os.umask(0)

        # Perform the second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                exit(0)
        except OSError, e:
            stderr.write('error: first fork failed: %d (%s)\n' % \
                (e.errno, e.strerror))
            exit(1)

        # redirect standard file descriptors
        stdout.flush()
        stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), stdin.fileno())
        os.dup2(so.fileno(), stdout.fileno())
        os.dup2(se.fileno(), stderr.fileno())

        # Register the function to delete the pidfile
        register(self.rmpid)
        try:
            pid = str(os.getpid())
        except:
            stderr.write('error: could not getpid()\n')
            exit(1)
        try:
            file(self.pidfile, 'w+').write('%s\n' % pid)
        except:
            stderr.write('error: could not write pidfile %s\n' \
                % self.pidfile)
            exit(1)

    def rmpid(self):
        '''Removes (unlink) the pidfile in the filesystem'''
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)

    def is_running(self):
        '''Determine if a copy of the daemon is already running'''
        # Get the pid from the pidfile
        pid = self.getpidfrompidfile()
        if not pid:
            return None
        try:
            os.kill(pid, 0)
        except OSError, err:
            return err.errno
        else:
            return 0

    def start(self):
        '''Starts the daemon'''

        # Access the global configuration dictionary
        global CONFIG

        if self.is_running() == 0:
            pid = self.getpidfrompidfile()
            msg = 'svnsyncd already running with pid: %s\n'
            stderr.write(msg % pid)
            exit(1)

        # Start the daemon unless we've been told to stay in the foreground
        if DAEMONIZED:
            self.double_fork_it()

        # Run the daemon
        self.run()

    def stop(self):
        '''Stops the daemon'''
        logentry('info: stopping the daemon...', LOG_INFO)

        pid = os.getpid()
        if not pid:
            msg = 'could not obtain pid. svnsyncd not running?\n'
            logentry(msg % self.pidfile, LOG_ERROR)
            return

        # Remove the pidfile
        self.rmpid()

        # Try killing the daemon process
        try:
            while 1:
                logentry('info: exiting...', LOG_INFO)
                os.killpg(-0, SIGKILL)
                sleep(1)
        except OSError, err:
            err = str(err)
            if err.find('No such process') > 0:
                self.rmpid()
            else:
                exit(1)

    def run(self):
        '''The default method for the SyncDaemon Class'''
        # Set up signal handling
        # The normal termination signal
        signal(SIGTERM, self.signal_handler)

        # The SIGUSR1 signal will handle a graceful restart
        signal(SIGUSR1, self.signal_handler)

        msg = 'info: starting daemon...'
        logentry(msg, LOG_INFO)

        # Access the global configuration dictionary
        global CONFIG

        # Access the global repository dataset
        global REPOS

        # Poll Interval
        global POLLINTERVAL

        # The Signals
        global SIGNAL_TERM
        global SIGNAL_USR1

        global SYNCTHREADS
        global SYNCTHREADS_MTX

        # Fill the REPOS dictionary
        reposdatasetthread = SVNSyncDBThread()
        reposdatasetthread.start()
        reposdatasetthread.join()

        loopcounter = 0
        while not SIGNAL_TERM: # MAIN LOOP
            try:
                if len(REPOS) > 0:
                    for name in REPOS:
                        while len(SYNCTHREADS) >= CONFIG['numthreads']:
                            for thread in SYNCTHREADS:
                                if not thread.isAlive():
                                    SYNCTHREADS.remove(thread)
                        if not REPOS[name]['mtx'].locked():
                            syncthread = SyncRepoThread(REPOS[name])
                            syncthread.start()
                            SYNCTHREADS.append(syncthread)
                        else:
                            if DEBUG_LOCK:
                                logentry('debug: SyncDaemon.run: ' \
                                    '%s mutex locked' % (name), LOG_DEBUG)
                            continue
            except:
                logentry('debug: SyncDaemon.run: REPOS has changed!', LOG_DEBUG)
            sleep(POLLINTERVAL)


class SyncRepoThread(Thread):
    def __init__(self, repo):
        Thread.__init__(self)
        self.repo = repo
        self.daemon = True

    def run(self):
        if not SIGNAL_TERM:
            self.sync_repo(self.repo)

    def unlock_repo(self, name, dst):
        '''Try to unlock a repository with a failing sync'''

        logentry('info: attempting to unlock repository: %s' % (name), LOG_INFO)

        # Access the global configuration dictionary
        global CONFIG

        # Access the global repository dataset
        global REPOS

        # If the repository replica is locked (e.g. due to failed sync attempt),
        # we need to delete the svn:sync-lock revision property to try again.
        oscmd = '%s propdel ' % (CONFIG['bin_svn'])
        oscmd += '-r0 --revprop svn:sync-lock '
        oscmd += '%s' % (dst)
        command = TimeCommander(oscmd)

        logentry('debug: SyncRepoThread.unlock_repo: %s' % (oscmd), LOG_DEBUG)

        try:
            (stdout, stderr, error) = command.run(timeout = 300)
            if (error == 0):
                msg = 'info: successfully unlocked repository: %s' % (name)
                logentry(msg, LOG_INFO)
                REPOS[name]['syncerror'] = False
            else:
                logentry('error: %s' % (stderr), LOG_ERROR)
                msg = 'error: could not unlock repository: %s' % (name)
                logentry(msg, LOG_ERROR)
                REPOS[name]['syncerror'] = True
        except:
            logentry('error: %s: %s)' \
                % (name, oscmd), LOG_ERROR)

    def sync_required(self, name, src, dst, user):
        '''Determine if a sync is required by comparing replica
        and source and destination repository revision numbers

        '''

        # The current source and destination revision
        rev_src = 0
        rev_dst = 0

        # Get the latest revision of the replica source.
        oscmd = '%s info ' % (CONFIG['bin_svn'])
        oscmd += '--username %s ' % (user)
        oscmd += '%s ' % (src)
        oscmd += '| grep "Revision" | cut -d":" -f2 '
        command = TimeCommander(oscmd)

        logentry('debug: SyncRepoThread.sync_required: %s' % (oscmd), LOG_DEBUG)

        (stdout, stderr, error) = command.run(timeout = 300)
        if (error != 0):
            logentry('error: %s: %s' % (name, oscmd), LOG_ERROR)
            return (False, 0, 0)
        else:
            try:
                rev_src = int(stdout)
            except:
                logentry('debug: SyncRepoThread.sync_required: '\
                    'invalid revision number %s: "%s"' \
                    % (src, stdout), LOG_DEBUG)
                return (False, 0, 0)
            msg = 'debug: SyncRepoThread.sync_required: ' \
                'source revision: %s' % (stdout)
            logentry(msg, LOG_DEBUG)

        # Get the latest revision of the replica destination.
        oscmd = '%s info ' % (CONFIG['bin_svn'])
        oscmd += '--username %s ' % (user)
        oscmd += '%s ' % (dst)
        oscmd += '| grep Revision | cut -d":" -f2 '
        command = TimeCommander(oscmd)

        logentry('debug: SyncRepoThread.sync_required: %s' % (oscmd), LOG_DEBUG)

        (stdout, stderr, error) = command.run(timeout = 300)

        if (error != 0):
            logentry('error: %s: %s' % (name, oscmd), LOG_ERROR)
            return (False, 0, 0)
        else:
            try:
                rev_dst = int(stdout)
            except:
                logentry('debug: SyncRepoThread.sync_required: ' \
                    'invalid revision number %s: "%s"' \
                    % (dst, stdout), LOG_DEBUG)
                return (False, 0, 0)
            msg = 'debug: SyncRepoThread.sync_required: ' \
                'destination revision: %s' % (stdout)
            logentry(msg, LOG_DEBUG)

        if (rev_dst < rev_src):
            logentry('info: sync required: %s %s %d %s %d' \
                % (name, src, rev_src, dst, rev_dst), LOG_INFO)
            return (True, rev_src, rev_dst)
        else:
            return (False, 0, 0)

    def sync_repo(self, repo):
        '''Run the svnsync process for the repository'''

        # Access the global configuration dictionary
        global CONFIG

        # Access the global repository dataset
        global REPOS

        # The Signals
        global SIGNAL_TERM
        global SIGNAL_USR1

        name = repo['name']
        src  = repo['src']
        dst  = repo['dst']
        user = CONFIG['syncuser']

        if DEBUG_LOCK:
            msg  = 'debug: SyncRepoThread.sync_repo: %s acquiring mutex %s' \
                % (name, REPOS[name]['mtx'])
            logentry(msg, LOG_DEBUG)

        REPOS[name]['mtx'].acquire()

        if not DEBUG_THREAD:
            (syncrequired, rev_src, rev_dst) = \
                self.sync_required(name, src, dst, user)

            if not syncrequired:
                logentry('debug: SyncRepoThread.sync_repo: ' \
                    '%s: sync not required' % (name), LOG_DEBUG)

                if DEBUG_LOCK:
                    msg  = 'debug: SyncRepoThread.sync_repo: ' \
                        '%s: releasing mutex %s' % (name, REPOS[name]['mtx'])
                    logentry(msg, LOG_DEBUG)

                REPOS[name]['mtx'].release()
                return 0
    
            msg = 'info: syncing: %s %s %d %s %d' \
                % (name, src, rev_src, dst, rev_dst)
            logentry(msg, LOG_INFO)
    
            # Run the `svnsync sync` command to perform the data transfer.
            REPOS[name]['syncing'] = True
            retry = 0
            oscmd = '%s sync ' % (CONFIG['bin_svnsync'])
            oscmd += '--sync-username %s ' % (user)
            oscmd += '--source-username %s ' % (user)
            oscmd += '%s' % (dst)
            command = TimeCommander(oscmd)

            # Sync the repository master configurations
            oscmd = '%s -i %s -r %s@%s:%s/conf.master %s/' % \
                (CONFIG['bin_scp'], CONFIG['scpkey'], CONFIG['scpuser'] \
                 REPOS['server'], REPOS['path'], REPOS['path'])

            logentry('debug: SyncRepoThread.sync_repo: %s' % (oscmd), LOG_DEBUG)
    
            while (retry <= CONFIG['retry']):

                # Run svnsync for no more than 24 hours (86,400 seconds).
                # (stdout, stderr, error) = command.run(timeout = 86400)

                # Run svnsync for no more than 8 hours (28,800 seconds).
                (stdout, stderr, error) = command.run(timeout = 28800)

                if (error != 0):
                    logentry('error: %s: %s' % (name, oscmd), LOG_ERROR)
                    REPOS[name]['syncerror'] = True
                    self.unlock_repo(name, dst)
                else:
                    REPOS[name]['syncing'] = False
                    msg  = 'info: syncing: %s is up-to-date' % (name)
                    logentry(msg, LOG_INFO)

                    if DEBUG_LOCK:
                        msg  = 'debug: SyncRepoThread.sync_repo: ' \
                            '%s: releasing %s' % (name, REPOS[name]['mtx'])
                        logentry(msg, LOG_DEBUG)

                    REPOS[name]['mtx'].release()
                    return 0

                retry = retry + 1
                sleep(CONFIG['retrywait'])
    
            logentry('error: %s: giving up, maximum retries attempted' \
                % (name), LOG_ERROR)

            if DEBUG_LOCK:
                msg  = 'debug: SyncRepoThread.sync_repo: %s: releasing %s' \
                    % (name, REPOS[name]['mtx'])
                logentry(msg, LOG_DEBUG)

            REPOS[name]['mtx'].release()

            return 1
        else:
            ###############################################################
            # DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
            # For debugging purposes, create a work item of random length
            # and return when the duration is up.
            ###############################################################
            global DEBUG_COUNTER
            if DEBUG_LOCK:
                msg  = 'debug: SyncRepoThread.sync_repo: ' \
                    '%s acquiring mutex %s' % (name, REPOS[name]['mtx'])
                logentry(msg, LOG_DEBUG)
            REPOS[name]['mtx'].acquire()
            num = randrange(1, 6, 1)
            mult = randrange(1, 6, 1)
            fact = randrange(1, 9, 1)
            div = randrange(1, 9, 1)
            sleept = (num * mult * fact) / div
            #DEBUG_COUNTER = DEBUG_COUNTER + 1
            #sleept = DEBUG_COUNTER
            oscmd = 'syncsleep %d' % (sleept)
            command = TimeCommander(oscmd)
            logentry('info: start:  %s %s' % (name, sleept), LOG_INFO)
            (stdout, stderr, error) = command.run(timeout = 300)
            logentry('info: finish: %s %s' % (name, sleept), LOG_INFO)
            if DEBUG_LOCK:
                msg  = 'debug: SyncRepoThread.sync_repo: %s: releasing %s' \
                    % (name, REPOS[name]['mtx'])
                logentry(msg, LOG_DEBUG)
            REPOS[name]['mtx'].release()


def main(argv):
    '''The main function for the program.'''

    global LOG_LEVEL
    global CONFIG
    global DAEMONIZED

    # Parse command line arguments and options.
    helpstr = '\nExamples:\n'
    helpstr += '  svnsyncd\n'
    helpstr += '  svnsyncd -d\n'
    usage = 'usage: %prog [options]\n' + helpstr
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--no-daemon', '-d', action='store_true',
                      dest='daemonize', default=False,
                      help='Run svnsyncd in the foreground')
    parser.add_option('--svnsyncd-config-file', '-f', action='store',
                      type='string', dest='configfile', default='',
                      help='Specify the main svnsyncd config file')

    (options, args) = parser.parse_args()

    if len(args) >= 1:
        errstr = 'Unknown option\n\n'
        errstr += 'For more details, try the -h option.\n'
        parser.error(errstr)

    # Configuration file override
    if options.configfile == '':
        configfile = '/data/etc/svnsyncd.conf'
    else:
        configfile = os.path.abspath(options.configfile)

    # Attempt to configure the daemon. If we fail, bail.
    CONFIG = configure_svnsyncd(configfile)
    if not CONFIG:
        stderr.write('error: configuration failed!\n')
        exit(1)

    # Set the global daemonize option based on user input.
    if options.daemonize:
        DAEMONIZED = False

    # Instantiate an SyncDaemon object
    svnsyncd_daemon = SyncDaemon()

    # Start the daemon
    svnsyncd_daemon.start()

    exit(0)

if __name__ == '__main__':
    '''Meta main() man, meta main()...'''
    main(argv[1:])

