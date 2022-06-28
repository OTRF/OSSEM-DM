#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)

import yaml
yaml.Dumper.ignore_aliases = lambda *args : True

###### Variables #####
current_directory = os.path.dirname(__file__)
relationships_directory = os.path.join(current_directory, '../relationships')
