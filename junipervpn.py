#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import binascii
import getpass
import hashlib
import hmac
import shlex
import signal
import subprocess
import sys
import time

from selenium import webdriver
from six import iteritems, print_
from six.moves import configparser



"""
OATH code from https://github.com/bdauvergne/python-oath
Copyright 2010, Benjamin Dauvergne

* All rights reserved.
* Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.'''
"""


def truncated_value(h):
    bytes = map(ord, h)
    offset = bytes[-1] & 0xf
    v = (bytes[offset] & 0x7f) << 24 | (bytes[offset+1] & 0xff) << 16 | \
        (bytes[offset+2] & 0xff) << 8 | (bytes[offset+3] & 0xff)
    return v


def dec(h, p):
    v = truncated_value(h)
    v %= 10**p
    return '%0*d' % (p, v)


def int2beint64(i):
    hex_counter = hex(long(i))[2:-1]
    hex_counter = '0' * (16 - len(hex_counter)) + hex_counter
    bin_counter = binascii.unhexlify(hex_counter)
    return bin_counter


def hotp(key):
    key = binascii.unhexlify(key)
    counter = int2beint64(int(time.time()) / 30)
    return dec(hmac.new(key, counter, hashlib.sha256).digest(), 6)


class JuniperVpn(object):
    def __init__(self, args):
        self.args = args
        self.fixed_password = args.password is not None
        self.last_connect = 0

        self.br = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true'])
        self.br.set_window_size(1024, 768)
        self.br.implicitly_wait(1)

        self.last_action = None
        self.needs_2factor = False
        self.key = None
        self.p = None
        self.shutting_down = False

    def find_cookie(self, name):
        return self.br.get_cookie(name)

    def next_action(self):
        if self.find_cookie('DSID'):
            return 'connect'

        for form in self.br.find_elements_by_tag_name('form'):
            form_name = form.get_attribute('name')
            if form_name == 'frmLogin':
                return 'login'
            elif form_name == 'frmDefender':
                return 'key'
            elif form_name == 'frmConfirmation':
                return 'continue'
            else:
                raise Exception('Unknown form type:', form_name)
        raise Exception('No form found!')

    def run(self):
        # Open landing page
        self.br.get('https://' + self.args.host)

        while True:
            if self.shutting_down:
                break

            action = self.next_action()
            if self.args.verbose:
                print_('Action:', action)
            elif action == 'login':
                self.action_login()
            elif action == 'key':
                self.action_key()
            elif action == 'continue':
                self.action_continue()
            elif action == 'connect':
                self.action_connect()

            self.last_action = action

    def action_login(self):
        # The token used for two-factor is selected when this form is submitted.
        # If we aren't getting a password, then get the key now, otherwise
        # we could be sitting on the two factor key prompt later on waiting
        # on the user.

        if self.args.password is None or self.last_action == 'login':
            if self.fixed_password:
                print_('Login failed (Invalid username or password?)')
                sys.exit(1)
            else:
                self.args.password = getpass.getpass('Password:')
                self.needs_2factor = False

        if self.needs_2factor:
            if self.args.oath:
                self.key = hotp(self.args.oath)
            else:
                self.key = getpass.getpass('Two-factor key:')
        else:
            self.key = None

        # Enter username/password
        self.post_form(
            username=self.args.username, password=self.args.password)

    def action_key(self):
        # Enter key
        self.needs_2factor = True
        if self.args.oath:
            if self.last_action == 'key':
                print_('Login failed (Invalid OATH key)')
                sys.exit(1)
            self.key = hotp(self.args.oath)
        elif self.key is None:
            self.key = getpass.getpass('Two-factor key:')

        self.post_form(password=self.key)

    def action_continue(self):
        # Yes, I want to terminate the existing connections
        checkboxes = self.br.find_elements_by_css_selector('input[type=checkbox]')
        for checkbox in checkboxes:
            checkbox.click()
        self.post_form()

    def action_connect(self):
        now = time.time()
        delay = 10.0 - (now - self.last_connect)
        if delay > 0:
            print_('Waiting %.0f...' % (delay))
            time.sleep(delay)
        self.last_connect = time.time()

        dsid = self.find_cookie('DSID')['value']
        action = []
        for arg in self.args.action:
            arg = arg.replace('%DSID%', dsid).replace('%HOST%', self.args.host)
            action.append(arg)

        print_('Running subcommand:', action)
        self.p = subprocess.Popen(action,
                                  stdin=subprocess.PIPE,
                                  universal_newlines=True)
        if args.stdin is not None:
            stdin = args.stdin.replace('%DSID%', dsid)
            stdin = stdin.replace('%HOST%', self.args.host)
            self.p.communicate(input=stdin)
        else:
            self.p.wait()
        ret = self.p.returncode
        self.p = None

        # Openconnect specific
        if ret == 2:
            print_('Connect command failed, retrying!')
            self.br.delete_cookie('DSID')
            self.br.get(self.br.current_url)
        else:
            print_('Connect command retcode:', ret)

    def post_form(self, **overrides):
        form = self.br.find_elements_by_tag_name('form')[0]
        for input_name, input_value in iteritems(overrides):
            input_elt = form.find_element_by_name(input_name)
            input_elt.send_keys(input_value)

        form.find_element_by_css_selector('input[type=submit]').click()

    def handle_signal(self, signum, frame):
        self.shutting_down = True
        if self.p and self.p.poll() is None:
            self.p.send_signal(signum)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler='resolve')
    parser.add_argument('-h', '--host', type=str,
                        help='VPN host name')
    parser.add_argument('-u', '--username', type=str,
                        help='User name')
    parser.add_argument('-o', '--oath', type=str,
                        help='OATH key for two factor authentication (hex)')
    parser.add_argument('-c', '--config', type=str,
                        help='Config file')
    parser.add_argument('-s', '--stdin', type=str,
                        help="String to pass to action's stdin")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Enable verbose output")
    parser.add_argument('action', nargs=argparse.REMAINDER,
                        metavar='<action> [<args...>]',
                        help='External command')

    args = parser.parse_args()
    args.__dict__['password'] = None

    if len(args.action) and args.action[0] == '--':
        args.action = args.action[1:]

    if not len(args.action):
        args.action = None

    if args.config is not None:
        config = configparser.RawConfigParser()
        config.read(args.config)
        for arg in ['username', 'host', 'password', 'oath', 'action', 'stdin', 'verbose']:
            if args.__dict__[arg] is None:
                try:
                    args.__dict__[arg] = config.get('vpn', arg)
                except configparser.Error:
                    pass

    if not isinstance(args.action, list):
        args.action = shlex.split(args.action)

    if args.username is None or args.host is None or args.action == []:
        print_("--user, --host, and <action> are required parameters")
        sys.exit(1)

    jvpn = JuniperVpn(args)
    signal.signal(signal.SIGINT, jvpn.handle_signal)
    signal.signal(signal.SIGTERM, jvpn.handle_signal)
    jvpn.run()

