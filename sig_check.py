#!/usr/bin/python3
"""Avaya signaling groups and other metrics status checker"""

import os
import sys
import time
import json
import socket
import logging
import subprocess
from logging.handlers import RotatingFileHandler
# Non-standard import
import paramiko


def log_config(level, logfile):
    """Logging configuration"""
    log = logging.getLogger('Avaya')
    log.setLevel(level)
    handler = RotatingFileHandler(logfile, maxBytes=5000000, backupCount=5)
    handler_console = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter(fmt='%(asctime)s: [%(levelname)s] %(message)s'))
    handler_console.setFormatter(logging.Formatter(fmt='%(message)s'))
    log.addHandler(handler_console)
    log.addHandler(handler)
    return log


def write_dump(host, key, result, filename):
    """Write line in dump file for zabbix_sender packet transmition"""
    with open(filename, 'a') as dump:
        timestamp = time.time()
        # Writing line in zabbix_sender format
        line = f'{host} {key} {int(timestamp)} {result}'
        dump.write(f'{line}\n')
        logger.debug('%s: %s', filename, line)


def send_dump(server, port, filename):
    """Sending dump file to zabbix trapper"""
    logger.info('Sending %s', filename)
    result = subprocess.run(['zabbix_sender', '-z', server, '-p', port, '-i', filename, '-T'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    os.remove(filename)
    logger.info(result.stdout.strip().replace('\n', ' '))


def avaya_connect(host, username, password, port=22):
    """Avaya OSSI connector"""
    channel = paramiko.SSHClient()
    channel.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        channel.connect(hostname=host, port=port, username=username, password=password,
            look_for_keys=False, allow_agent=False)
        session = channel.invoke_shell()
        time.sleep(2)
        session.send('ossi\n')
        session.recv(1000)
    except (paramiko.SSHException, OSError) as conn_err:
        logger.error(conn_err)
        sys.exit()
    time.sleep(1)
    logger.info('Connected to station %s', host)
    return channel, session


def cmd_exec(session, command, timeout=0.5):
    """Console command line executor"""
    try:
        result = ''
        session.settimeout(timeout)
        session.send(command)
        while True:
            try:
                result += session.recv(1000).decode('utf-8')
                time.sleep(0.05)
            except socket.timeout:
                break
    except paramiko.SSHException as sess_err:
        logger.error(sess_err)
        return False
    return result


def ossi_parse(raw_data):
    """Avaya OSSI output data parser to objects list"""
    fields = []
    data = []
    lines = raw_data.split('\n')
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
    logger.debug(ossi_result)
    return ossi_result


def item_get(ossi_result, item_name, location_id, location):
    """Item selector"""
    try:
        item = ossi_result[location_id][location]
    except (IndexError, KeyError):
        logger.error('Inconsistent data (%s): %s',
            item_name, output.replace('\r', ' ').replace('\n', ' ').replace('\t', ' '))
        return False
    return item


if __name__ == '__main__':
    if not sys.argv[1:]:
        print(f'Usage: {sys.argv[0]} station.json [zabbix:port] [LOGLEVEL]')
        sys.exit()
    with open(sys.argv[1]) as jsonfile: station = json.load(jsonfile)
    zbx_server = '127.0.0.1'
    zbx_port = '10051'
    if sys.argv[2:]:
        zbx_server = sys.argv[2].split(':')[0]
        zbx_port = sys.argv[2].split(':')[1]
    log_level = 'INFO'
    if sys.argv[3:]: log_level = sys.argv[3]
    logger = log_config(log_level, f"{station['host']}.log")
    lastfile = f"{station['host']}.last"
    dumpfile = f"{station['host']}.dump"

    exec_start = time.monotonic()
    cl, ssh = avaya_connect(station['ip'], station['user'], station['password'], station['port'])

    # Signaling groups
    for siggrp in station['siggrps']:
        # Starting polling cycle iteration
        logger.debug('Polling signaling group %s', siggrp)
        query_start = time.monotonic()
        output = cmd_exec(ssh, f'csta sig {siggrp}\nt\n', station['timeout'])
        parsed_output = ossi_parse(output)
        status = item_get(parsed_output, siggrp, 0, '0003ff00')
        if status is False:
            continue
        if status == 'in-service':
            state = 1
        else:
            logger.warning('Signaling group %s in status %s', siggrp, status)
            state = 0
        write_dump(station['host'], f'siggrp[{siggrp}]', state, dumpfile)
        query_time = round((time.monotonic() - query_start), 2)
        logger.debug('Query time: %s s', query_time)

    # Other metrics
    logger.debug('Polling IP phones')
    output = cmd_exec(ssh, 'cdisplay system-parameters customer-options\nt\n', station['timeout'])
    parsed_output = ossi_parse(output)
    if parsed_output:
        for field, data in parsed_output[0].items():
            if data == 'IP_Phone': break
        ip_phones = item_get(parsed_output, 'IP phones', 0, '6e23'+field[4:])
        if ip_phones is not False:
            logger.info('IP phones: %s', ip_phones)
            write_dump(station['host'], 'ip_phones', ip_phones, dumpfile)

    logger.debug('Polling media gateways')
    output = cmd_exec(ssh, 'cstatus media-gateways\nt\n', station['timeout'])
    parsed_output = ossi_parse(output)
    media_gw = item_get(parsed_output, 'Media gateways', 0, '6c0bff00')
    if media_gw is not False:
        logger.info('Media gateways: %s', media_gw)
        write_dump(station['host'], 'media_gw', media_gw, dumpfile)

    logger.debug('Polling active calls')
    output = cmd_exec(ssh, 'clist measurements occupancy last-hour\nt\n', station['timeout'])
    parsed_output = ossi_parse(output)
    calls = item_get(parsed_output, 'Calls', 0, '000bff00')
    if calls is not False:
        logger.info('Calls: %s', calls)
        write_dump(station['host'], 'calls', calls, dumpfile)

    logger.debug('Checking last day alarms')
    # PARAMS: Active(y) Resolved(n) Major(y) Minor(y) Warning(n) Interval(d)
    output = cmd_exec(ssh, f'cdisplay alarms\n'
                           f'f0001ff00\t0002ff00\t0003ff00\t0004ff00\t0005ff00\t0010ff00\n'
                           f'dy\tn\ty\ty\tn\td\n'
                           f't\n', station['timeout'])
    parsed_output = ossi_parse(output)
    #print(json.dumps(parsed_output, indent=4))
    last_clock, max_clock = 0, 0
    if os.path.isfile(lastfile):
        with open(lastfile) as clockfile: last_clock = int(clockfile.read())
    messages = []
    for record in parsed_output:
        try:
            # Month+Day+Hour+Mins string
            clock = int(record['000eff00']+record['0006ff00']+record['0007ff00']+record['0008ff00'])
            if clock > last_clock:
                # DD.MM HH:MM Severity Port Name AltName Onboard SvcState
                message = f"{record['0006ff00']}.{record['000eff00']} {record['0007ff00']}:{record['0008ff00']} "\
                          f"{record['0005ff00']} {record['0001ff00']} {record['0002ff00']} {record['0004ff00']} "\
                          f"ONBOARD:{record['0003ff00']} {record['000cff00']}"
                messages.append(message)
                logger.warning('New alarm: %s', message)
                if clock > max_clock: max_clock = clock
        except (TypeError, KeyError):
            logger.error('Unable to parse log record: %s', record)
    if messages:
        message_dump = ' ; '.join(messages) # Concatinating messages
        message_dump = f'"{" ".join(message_dump.split())}"' # Removing multiple spaces, adding qoutes
        write_dump(station['host'], 'alarms', message_dump, dumpfile)
    if max_clock:
        with open(lastfile, 'w') as clockfile: clockfile.write(str(max_clock))

    if 'trunkgrps' in station:
        logger.debug('Polling trunk groups')
        for group in station['trunkgrps']:
            groupstart = group[0] # First list element is a start position for group selector
            output = cmd_exec(ssh, f'cmonitor traffic trunk-groups {groupstart}\nt\n', station['timeout'])
            parsed_output = ossi_parse(output)
            if not parsed_output: continue
            for data in parsed_output[0].values():
                data_arr = data.split()
                for trunkgrp in group[1:]:
                    if str(trunkgrp) != data_arr[0]: continue
                    try:
                        write_dump(station['host'], f'trunk[{trunkgrp}]', data_arr[2], dumpfile)
                    except IndexError:
                        pass

    cl.close()
    if os.path.isfile(dumpfile):
        send_dump(zbx_server, zbx_port, dumpfile)
    exec_time = round(time.monotonic() - exec_start)
    m, s = divmod(exec_time, 60)
    logger.info('Execution time: %sm %ss\n', m, s)
