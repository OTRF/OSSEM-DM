import glob
import os
import re
from datetime import date

current_directory = os.path.dirname(__file__)
relationships_directory = os.path.join(current_directory, '../relationships')
max_id=0
num_id = dict() # a dictionary with year as key and list of numbers as values
relationships_files = glob.glob(os.path.join(relationships_directory, "[!_]*.yml"))
for relationship_file in relationships_files:
    file = open(relationship_file,'r+')
    first_line = file.readlines()[0].rstrip() # read first line
    if re.search("^relationship_id\:\sREL\-[\d]{4}\-\d{4}", first_line): # If file already has an ID
        search = re.search("^relationship_id\:\sREL\-([\d]{4})\-([\d]{4})$", first_line) # Grab it
        if search.group(1) not in num_id.keys(): # adding year as key of the dict
            num_id[search.group(1)] = []
        num_id[search.group(1)].append(int(search.group(2))) # adding number to corresponding key

current_date = date.today()
year = str(current_date.year)
if year not in num_id.keys():
    print('relationship_id: REL-' + year + '-' + '0001') # First relationship of the year
else:
    number = max(num_id[year])+1
    print('relationship_id: REL-' + year + '-' + '0'*(4 - len(str(number))) + str(number))
