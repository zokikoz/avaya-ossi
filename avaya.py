#!/usr/bin/python3
"""Avaya OSSI connector"""

import sys
import time
import json
import socket
# Non-standard import
import paramiko


if __name__ == '__main__':
    if not sys.argv[4:]:
        print(f'Usage: {sys.argv[0]} host username password command [port]')
        sys.exit()

    max_bytes = 60000
    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    command = sys.argv[4]
    if not sys.argv[5:]:
        port = 22
    else:
        port = sys.argv[5]

    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cl.connect(hostname=host, port=port, username=username, password=password,
            look_for_keys=False, allow_agent=False)
        with cl.invoke_shell() as ssh:
            time.sleep(2)
            ssh.send('ossi\n')
            ssh.recv(max_bytes)
            ssh.settimeout(1)
            result = ''
            ssh.send(f'c{command}\nt\n')
            while True:
                try:
                    result += ssh.recv(max_bytes).decode('utf-8')
                    time.sleep(0.2)
                except socket.timeout:
                    break
    except (paramiko.SSHException, OSError) as conn_err:
        print(conn_err)
        sys.exit()
    #print(result)

    # Parsing OSSI output
    fields = []
    data = []
    lines = result.split('\n')
    for line in lines:
        if line.startswith('f'): fields.append(line[1:].split('\t'))
        elif line.startswith('d'): data.append(line[1:].split('\t'))
    data_object = {}
    ossi_result = []
    field_line = 0
    for dataline in data:
        for index, item in enumerate(dataline):
            data_object[fields[field_line][index]] = dataline[index]
        field_line += 1
        if field_line == len(fields):
            ossi_result.append(data_object)
            field_line = 0
            data_object = {}
    print(json.dumps(ossi_result))
