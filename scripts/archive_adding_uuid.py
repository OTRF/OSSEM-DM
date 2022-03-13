#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)


import glob
import os

# if UUID is required
# import uuid
# to_write = 'uuid: ' + str(uuid.uuid4()).upper()+'\n'

###### Variables #####
current_directory = os.path.dirname(__file__)
relationships_directory = os.path.join(current_directory, '../relationships')

print("[+] Adding UUID to the beggining of relationships yaml files..")
relationships_files = glob.glob(os.path.join(relationships_directory, "[!_]*.yml"))
count = 1
for relationship_file in relationships_files:
    file = open(relationship_file,'r+')
    file_lines = file.readlines() # read current content
    file.seek(0) # Going to the beggining of the file
    to_write = 'relationship_id: REL-2022-' + '0'*(4 - len(str(count))) + str(count)+'\n'
    file.write(to_write) # write the new text
    for line in file_lines:
        file.write(line)
    file.close()
    count +=1