import glob
import os
import re

current_directory = os.path.dirname(__file__)
relationships_directory = os.path.join(current_directory, '../relationships')
max_id=0
num_id = []
relationships_files = glob.glob(os.path.join(relationships_directory, "[!_]*.yml"))
for relationship_file in relationships_files:
    file = open(relationship_file,'r+')
    first_line = file.readlines()[0].rstrip() # read first line
    if re.search("^relationship_id\:\sREL\-202[\d]{1}\-\d{4}", first_line): # If file already has an ID
        search = re.search("^relationship_id\:\sREL\-202[\d]{1}\-(.*?)$", first_line) # Grab it
        num_id.append(search.group(1))
# Convert strings to integers
for i in range(0, len(num_id)):
    num_id[i] = int(num_id[i])
# Get max ID in list
for n in num_id:
    if n > max_id: max_id = n
# Generate relationship_id
count = max_id+1
print('relationship_id: REL-2022-' + '0'*(4 - len(str(count))) + str(count))