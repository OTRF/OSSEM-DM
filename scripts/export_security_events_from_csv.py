#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)

import csv

event_list = []
with open('/Users/cyb3rward0g/Downloads/WindowsSecurityAuditEvents.csv') as file:
    reader = csv.DictReader(file)
    for row in reader:
        event = dict()
        event[row['Event ID']] = row['Message Summary']
        if event not in event_list:
            event_list.append(event)
