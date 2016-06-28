"""Contains general utility functions to be used by the execution server."""

import os
import json
import sys
import subprocess
import threading


def load_configuration():
    config_file_name = os.path.join(os.path.dirname(__file__), 'config.json')
    config = json.load(open(config_file_name))
    return config


def process_commandline_args(register, update):
    if len(sys.argv) > 1:
        if sys.argv[1] == 'register':
            register()
            print('Successfully registered.')
            sys.exit(0)
        elif sys.argv[1] == 'update':
            update()
            print('Successfully updated.')
            sys.exit(0)
        else:
            print('Python custom execution server can take one of two optional arguments:')
            print('register - register the execution server with details from config.json')
            print('update - update the details of the execution server to those in config.json')
            sys.exit(1)


def run_background_thread(target, args=()):
    background_thread = threading.Thread(target=target, args=args)
    background_thread.daemon = True
    background_thread.start()


class ProcessRunner():
    def __init__(self):
        self._current_processes = {}
        self._stopping_processes = []

    def execute(self, command, identifier):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self._current_processes[identifier] = process
        output = ''
        for line in iter(process.stdout.readline, b''):
            output += line
        process.communicate()
        self._current_processes.pop(identifier, None)
        if identifier in self._stopping_processes:
            self._stopping_processes.remove(identifier)
            return None
        return output, process.returncode

    def stop(self, identifier):
        process = self._current_processes.get(identifier)
        if process is not None:
            self._stopping_processes.append(identifier)
            process.kill()