#### This file is altered from the Categorized Adversary TTPs project by tropChaud

# Copyright (c) 2022 IntelScott

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import requests
import json
import re

# Change to False to limit the resulting file to only include the actors that have an entry in MITRE ATT&CK.
FULL_ETDA = True

print("Retrieving MITRE ATT&CK")
# MITRE Groups https://attack.mitre.org/groups/
mitre_actors = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
mitre_actors = mitre_actors.json()

mitre_actor_list = []
for adversary in mitre_actors['objects']:
    mitre_actor_dict = {}
    if adversary['type'] == 'intrusion-set':
        mitre_actor_dict['id'] = adversary['id']
        mitre_actor_dict['name'] = adversary['name']
        created = adversary['created']
        created = created.split('T')
        mitre_actor_dict['created'] = created[0]
        last_modified = adversary['modified']
        last_modified = last_modified.split('T')
        mitre_actor_dict['last_modified'] = last_modified[0]
        mitre_actor_dict['variations'] = []
        mitre_actor_dict['variations_custom'] = []
        external_references = adversary['external_references']
        for reference in external_references:
            if 'external_id' in reference.keys():
                mitre_actor_dict['url'] = reference['url']
        try:
            variations = adversary['aliases']
            for variation in variations:
                mitre_actor_dict['variations'].append(variation)
        except KeyError:
            mitre_actor_dict['variations'].append(adversary['name'])

        variations_custom = []
        for item in mitre_actor_dict['variations']:
            variation_upper = item.upper()
            variations_custom.append(variation_upper)
            if ' ' in variation_upper:
                variation_noSpace = variation_upper.replace(' ', '')
                variations_custom.append(variation_noSpace)
            if '-' in variation_upper:
                variation_noDash = variation_upper.replace('-', '')
                variations_custom.append(variation_noDash)
            try:
                if '-' in variation_noSpace:
                    variation_noSpace_noDash = variation_noSpace.replace('-', '')
                    variations_custom.append(variation_noSpace_noDash)
            except NameError:
                continue
        for i in variations_custom:
            mitre_actor_dict['variations_custom'].append(i)

        mitre_actor_list.append(mitre_actor_dict)

# Populate MITRE Group TTPs
for mitre_actor in mitre_actor_list:
    technique_list = []
    actorID = mitre_actor['id']
    ttp_patternIDs = []
    for object_relationships in mitre_actors['objects']:
        try:
            if object_relationships['source_ref'] == actorID:
                if 'attack-pattern' in object_relationships['target_ref']:
                    ttp_patternIDs.append(object_relationships['target_ref'])
        except KeyError:
            continue
    for patternID in ttp_patternIDs:
        for object_ttp in mitre_actors['objects']:
            if object_ttp['id'] == patternID:
                try:
                    for external_reference in object_ttp['external_references']:
                        try:
                            if 'CAPEC' not in external_reference['external_id']:
                                technique_list.append(external_reference['external_id'])
                        except KeyError:
                            continue
                except KeyError:
                    continue

    mitre_actor['TTPs'] = technique_list

print("Retrieving ETDA MISP")
# ETDA Actors https://apt.etda.or.th/cgi-bin/listgroups.cgi
etda_actors = requests.get('https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g')
etda_actors = etda_actors.json()

print("Retrieving ETDA Cards")
# Build dictionary from alternative ETDA JSON file to include operation dates
etda_actor_cards = requests.get('https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=j')
etda_actor_cards = etda_actor_cards.json()

operations_dict = {}

for actor in etda_actor_cards['values']:
    date_list = []
    year_list = []
    if 'operations' in actor.keys():
        for operation in actor['operations']:
            date_list.append(operation['date'])
            year_list.append(operation['date'][:4])
    operations_dict[actor['uuid']] = (date_list,year_list)

etda_actor_list = []
for adversary in etda_actors['values']:
    etda_actor_dict = {}
    etda_actor_dict['id'] = adversary['uuid']
    name = adversary['value']
    etda_actor_dict['name'] = name
    name = name.replace('[', '')
    name = name.replace(']', '')
    name_list = re.split(', |,', name)
    etda_actor_dict['variations'] = []
    etda_actor_dict['variations_custom'] = []
    metadata = adversary['meta']
    etda_actor_dict['url'] = 'https://apt.etda.or.th/cgi-bin/showcard.cgi?u=' + adversary['uuid']
    try:
        etda_actor_dict['created'] = metadata['date']
    except KeyError:
        etda_actor_dict['created'] = 'None Provided'
    try:
        for variation in metadata['synonyms']:
            variation = variation.replace('[', '')
            variation = variation.replace(']', '')
            etda_actor_dict['variations'].append(variation)
        for name_variation in name_list:
            if name_variation not in etda_actor_dict['variations']:
                etda_actor_dict['variations'].append(name_variation)
    except KeyError:
        for name_variation in name_list:
            if name_variation not in etda_actor_dict['variations']:
                etda_actor_dict['variations'].append(name_variation)
    if 'country' in metadata.keys():
        etda_actor_dict['country'] = metadata['country']
    if 'motivation' in metadata.keys():
        etda_actor_dict['motivation'] = metadata['motivation']
    if 'cfr-target-category' in metadata.keys():
        etda_actor_dict['targeted_industries'] = metadata['cfr-target-category']
    if 'cfr-suspected-victims' in metadata.keys():
        etda_actor_dict['targeted_countries'] = metadata['cfr-suspected-victims']

    op_date, op_year = [],[]

    try:
        op_date,op_year = operations_dict[adversary['uuid']]
    except:
        print("{} not present in ETDA group cards".format(adversary['uuid']))

    etda_actor_dict['operation_date'] = op_date
    etda_actor_dict['operation_year'] = op_year

    variations_custom = []
    for item in etda_actor_dict['variations']:
        variation_upper = item.upper()
        variations_custom.append(variation_upper)
        if ' ' in variation_upper:
            variation_noSpace = variation_upper.replace(' ', '')
            variations_custom.append(variation_noSpace)
        if '-' in variation_upper:
            variation_noDash = variation_upper.replace('-', '')
            variations_custom.append(variation_noDash)
        try:
            if '-' in variation_noSpace:
                variation_noSpace_noDash = variation_noSpace.replace('-', '')
                variations_custom.append(variation_noSpace_noDash)
        except NameError:
            continue
    for i in variations_custom:
        etda_actor_dict['variations_custom'].append(i)

    etda_actor_list.append(etda_actor_dict)

# Comparison
etda_merged_ids = []
merge_list = []
id_check = []

print("Merging...")

for mitre_actor in mitre_actor_list:
    for mitre_variation in mitre_actor['variations_custom']:
        for etda_actor in etda_actor_list:
            if mitre_variation in etda_actor['variations_custom']:
                # Start compiling final data
                merge_dict = {}
                if mitre_actor['id'] in id_check:
                    continue
                else:
                    id_check.append(mitre_actor['id'])
                    etda_merged_ids.append(etda_actor['id'])

                    merge_dict['mitre_attack_id'] = mitre_actor['id']
                    merge_dict['mitre_attack_name'] = mitre_actor['name']
                    merge_dict['mitre_attack_aliases'] = mitre_actor['variations']
                    merge_dict['mitre_attack_created'] = mitre_actor['created']
                    merge_dict['mitre_attack_last_modified'] = mitre_actor['last_modified']
                    merge_dict['mitre_url'] = mitre_actor['url']
                    merge_dict['etda_id'] = etda_actor['id']
                    merge_dict['etda_name'] = etda_actor['name']
                    merge_dict['etda_aliases'] = etda_actor['variations']
                    merge_dict['etda_first_seen'] = etda_actor['created']
                    merge_dict['etda_url'] = etda_actor['url']
                    merge_dict['etda_operation_dates'] = etda_actor['operation_date']
                    merge_dict['etda_operation_year'] = etda_actor['operation_year']

                    if 'country' in etda_actor.keys():
                        merge_dict['country'] = etda_actor['country']
                    else:
                        merge_dict['country'] = 'None Provided'
                    if 'motivation' in etda_actor.keys():
                        merge_dict['motivation'] = etda_actor['motivation']
                    else:
                        merge_dict['motivation'] = 'None Provided'
                    if 'targeted_industries' in etda_actor.keys():
                        merge_dict['victim_industries'] = etda_actor['targeted_industries']
                    else:
                        merge_dict['victim_industries'] = 'None Provided'
                    if 'targeted_countries' in etda_actor.keys():
                        merge_dict['victim_countries'] = etda_actor['targeted_countries']
                    else:
                        merge_dict['victim_countries'] = 'None Provided'
                    merge_dict['mitre_attack_ttps'] = mitre_actor['TTPs']

                    merge_list.append(merge_dict)

if FULL_ETDA:
    for etda_actor in etda_actor_list:
        if etda_actor['id'] not in etda_merged_ids:
            # Start compiling final data
            merge_dict = {}
        
            merge_dict['mitre_attack_id'] = "Not Available"
            merge_dict['mitre_attack_name'] = "Not Available"
            merge_dict['mitre_attack_aliases'] = "Not Available"
            merge_dict['mitre_attack_created'] = "Not Available"
            merge_dict['mitre_attack_last_modified'] = "Not Available"
            merge_dict['mitre_url'] = "Not Available"
            merge_dict['etda_id'] = etda_actor['id']
            merge_dict['etda_name'] = etda_actor['name']
            merge_dict['etda_aliases'] = etda_actor['variations']
            merge_dict['etda_first_seen'] = etda_actor['created']
            merge_dict['etda_url'] = etda_actor['url']
            merge_dict['etda_operation_dates'] = etda_actor['operation_date']
            merge_dict['etda_operation_year'] = etda_actor['operation_year']
            if 'country' in etda_actor.keys():
                merge_dict['country'] = etda_actor['country']
            else:
                merge_dict['country'] = 'None Provided'
            if 'motivation' in etda_actor.keys():
                merge_dict['motivation'] = etda_actor['motivation']
            else:
                merge_dict['motivation'] = 'None Provided'
            if 'targeted_industries' in etda_actor.keys():
                merge_dict['victim_industries'] = etda_actor['targeted_industries']
            else:
                merge_dict['victim_industries'] = 'None Provided'
            if 'targeted_countries' in etda_actor.keys():
                merge_dict['victim_countries'] = etda_actor['targeted_countries']
            else:
                merge_dict['victim_countries'] = 'None Provided'
            merge_dict['mitre_attack_ttps'] = "Not Available"

            merge_list.append(merge_dict)

print("Writing to file")
with open('data/ETDA_ATTCK_merge.json', 'w', encoding='utf-8') as outfile:
    json.dump(merge_list, outfile, indent=2, ensure_ascii=False)