#!/usr/bin/env python
#-*- coding: utf-8 -*-

'''
Usage:
  dnspod_ddns.py [options]

Options:
  -h --help      Show this screen.
  -t TIME        Check IP change every TIME seconds [default: 60].
  -l LOG_PATH    Program log file [default: /var/log/dnspod_ddns.log].
  -p PID_FILE    Use PID_FILE as daemon's pid file [default: /var/run/dnspod_ddns.pid]
  -d ACTION      Run this script as a daemon (e.g. start,stop,restart).

'''

def handle_import_error():
    print('Please install 3rd-party modules required by dnspod_ddns.py with following command:')
    print('  sudo pip install -r requirements.txt')
    import sys
    sys.exit()

try:
    from daemon import runner
except ImportError:
    handle_import_error()
import docopt
import logging
import logging.handlers
import os
import socket
import sys
import time


try:
    from dnspod.base import BaseAPI
    from dnspod.domain import DomainAPI
    from dnspod.record import Record, RecordAPI
except ImportError:
    handle_import_error()

#import config
import json
def load_config(filename):
    with open(filename) as file:
        text = file.read()
        js = json.loads(text)
        return js

class SubDomain:
    def __init__(self, name, rec, is_local):
        self.name = name
        self.record = rec
        if is_local == "False":
            self.is_local = False;
        else:
            self.is_local = True;
        self.last_ip = "0.0.0.0"

class App(object):
    '''
    main application called by daemon.runner
    '''

    def __init__(self, args):
        self.stdin_path = os.devnull
        self.stdout_path = os.devnull
        self.stderr_path = os.devnull
        self.pidfile_path = args['-p']
        self.pidfile_timeout = 3

        self._args = args
        self.config = load_config("./config.json")

    def run(self):
        # Set up logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(asctime)s %(levelname)s] %(message)s')
        if self._args['-d'] == None:
            handler = logging.StreamHandler()
        else:
            handler = logging.handlers.RotatingFileHandler(self._args['-l'],
                                                           maxBytes=1*1024*1024,
                                                           backupCount=1)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        if self._args['-d'] in ['start']:
            time.sleep(int(self._args['-t']))

        while True:
            bapi = BaseAPI(self.config["LOGIN_EMAIL"], self.config["LOGIN_PASSWORD"])
            dapi = DomainAPI(bapi)
            rapi = RecordAPI(bapi)
            domain = dapi.info(domain=self.config["DOMAIN"])
            record_list = rapi.list(domain.id)
            sub_domains = dict()
            for rec in record_list:
                for sub_domain in self.config["SUB_DOMAIN"]:
                    sub_domain_name = sub_domain["name"]
                    if rec.sub_domain == sub_domain_name and rec.record_type == Record.TYPE_A:
                        sub_domains[sub_domain_name] = SubDomain(sub_domain_name, rec, sub_domain["isLocal"])
            # if record == None or record_local == None:
            #     logger.error("Couldn't get A record of domain: %s.%s",
            #                 config.SUB_DOMAIN, config.DOMAIN)
            #     time.sleep(int(self._args['-t']))
            # else:
            break

        for key in sub_domains:
            sub_domains[key].last_ip = sub_domains[key].record.value

        while True:
            for key in sub_domains:
                sub_domain = sub_domains[key]
                record = sub_domain.record
                last_ip = sub_domain.last_ip
                try:
                    if sub_domain.is_local:
                        current_ip = get_local_ip()
                    else:
                        current_ip = get_ip()
                except socket.error, e:
                    logger.error('Get current IP error: %s', e)
                else:
                    changed = False
                    if current_ip != last_ip:
                        logger.info('IP change from %s to %s, update DNS record',
                                    last_ip, current_ip)
                        rapi.ddns(record.domain_id, record.id, record.sub_domain,
                                  record.record_line, current_ip)
                        last_ip = current_ip
                        changed = True

                    if not changed:
                        logger.info('IP not change, check after %d seconds',
                                    int(self._args['-t']))
            time.sleep(int(self._args['-t']))

def get_ip():
    sock = socket.create_connection(('ns1.dnspod.net', 6666), timeout=30)
    ip = sock.recv(16)
    sock.close()
    return ip

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def main():
    try:
        arguments = docopt.docopt(__doc__)
    except docopt.DocoptExit:
        print(__doc__.strip())
        return
    app = App(arguments)
    action = arguments['-d']
    if action != None:
        if action in ['start', 'stop', 'restart']:
            sys.argv[1] = action
            daemon_runner = runner.DaemonRunner(app)
            daemon_runner.do_action()
        else:
            print(__doc__.strip())
            return
    else:
        app.run()

if __name__ == '__main__':
    main()
