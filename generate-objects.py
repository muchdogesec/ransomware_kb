import pandas as pd
import uuid
import datetime
import os
import requests
import shutil
from stix2 import (IntrusionSet, Malware, Tool, Relationship, ExternalReference, FileSystemStore, Bundle, parse)

# Namespace for UUID generation
NAMESPACE_UUID = uuid.UUID('221c1248-e62e-56e5-bbfb-7d5efc477271')
IDENTITY_ID = 'identity--221c1248-e62e-56e5-bbfb-7d5efc477271'
V0_1_RELEASE = "2024-08-22T00:00:00.000Z"

# Define the output directory
output_directory = './stix2_objects'

# Delete the stix2_objects directory if it exists
if os.path.exists(output_directory):
    shutil.rmtree(output_directory)
    print(f"Deleted existing directory: {output_directory}")

# Recreate the stix2_objects directory
os.makedirs(output_directory, exist_ok=True)

# Initialize FileSystemStore
fs_store = FileSystemStore(output_directory)

# Function to generate consistent UUIDv5
def generate_uuid(name):
    if name is None or not isinstance(name, str) or name.strip() == "":
        raise ValueError(f"The 'name' for UUID generation must be a non-empty string. Invalid value: {name}")
    return str(uuid.uuid5(NAMESPACE_UUID, name.strip()))

# Function to create an external reference
def create_external_references(row):
    references = []
    if pd.notna(row.get('external_id')):
        references.append(ExternalReference(
            source_name="ransomware-kb",
            external_id=row['external_id']
        ))
    if pd.notna(row.get('mitre_attack_id')):
        references.append(ExternalReference(
            source_name="mitre-attack",
            external_id=row['mitre_attack_id']
        ))
    for col in row.index:
        if col.startswith('ref.') and pd.notna(row[col]) and isinstance(row[col], str):
            ref_name = col.split('ref.')[-1]
            references.append(ExternalReference(
                source_name=ref_name,
                description=row[col]
            ))
    return references

# Function to safely split strings
def safe_split(string, delimiter='\n'):
    if isinstance(string, str):
        return [s.strip() for s in string.split(delimiter) if s.strip()]
    return []

# Function to add an object to the store
def add_object(stix_object):
    try:
        fs_store.add(stix_object)
        return stix_object  # Return the object to include it in the bundle
    except Exception as e:
        print(f"Error adding object {stix_object.id}: {e}")
        return None

# Function to download and parse a STIX object from a URL
def download_stix_object(url):
    response = requests.get(url)
    response.raise_for_status()
    return parse(response.text)

# Download and process marking definition
MARKING_DEFINITION_URL = 'https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/ransomware_kb.json'
marking_definition = download_stix_object(MARKING_DEFINITION_URL)
added_object = add_object(marking_definition)
all_objects_for_bundle = []
if added_object:
    all_objects_for_bundle.append(added_object)

# Download and process identity
IDENTITY_URL = 'https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/ransomware_kb.json'
identity = download_stix_object(IDENTITY_URL)
added_object = add_object(identity)
if added_object:
    all_objects_for_bundle.append(added_object)

# Load the spreadsheet with the correct file path
file_path = 'data/ransomware_kb_master.xlsx'
xl = pd.ExcelFile(file_path)

# Function to create platform list
def get_platforms(row):
    platforms = [platform.split('.')[1] for platform in row.index if platform.startswith('platform.') and pd.notna(row[platform]) and row[platform]]
    return platforms

# Process the 'Intrusion Set - Groups' tab
groups_df = xl.parse('Intrusion Set - Groups')
for index, row in groups_df.iterrows():
    try:
        name = row['name']
        object_id = 'intrusion-set--' + generate_uuid(name)
        print(f"Processing Intrusion Set: {name}")

        # Create the new object
        intrusion_set = IntrusionSet(
            type='intrusion-set',
            id=object_id,
            created=V0_1_RELEASE,
            modified=V0_1_RELEASE,
            created_by_ref=IDENTITY_ID,
            name=name,
            description=row.get('description', ''),
            aliases=safe_split(row.get('aliases', '')),
            external_references=create_external_references(row),
            object_marking_refs=[
                marking_definition.id,
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ],
            allow_custom=True
        )

        added_object = add_object(intrusion_set)
        if added_object:
            all_objects_for_bundle.append(added_object)

    except Exception as e:
        print(f"Error processing row {index} in 'Intrusion Set - Groups': {e}")

# Process the 'Malware - Ransomware' tab
ransomware_df = xl.parse('Malware - Ransomware')
malware_map = {}
for index, row in ransomware_df.iterrows():
    try:
        name = row['name']
        object_id = 'malware--' + generate_uuid(name)
        print(f"Processing Malware: {name}")

        platforms = get_platforms(row)  # Get platforms using the helper function
        malware = Malware(
            type='malware',
            id=object_id,
            created=V0_1_RELEASE,
            modified=V0_1_RELEASE,
            created_by_ref=IDENTITY_ID,
            name=name,
            description=row.get('description', ''),
            is_family=True,
            aliases=safe_split(row.get('aliases', '')),
            external_references=create_external_references(row),
            object_marking_refs=[
                marking_definition.id,
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ],
            allow_custom=True,
            **({'x_mitre_platforms': platforms} if platforms else {})  # Only include if platforms are non-empty
        )

        added_object = add_object(malware)
        if added_object:
            all_objects_for_bundle.append(added_object)
            malware_map[row['external_id']] = malware

    except Exception as e:
        print(f"Error processing row {index} in 'Malware - Ransomware': {e}")

# Process the 'Tool - Tools' tab
tools_df = xl.parse('Tool - Tools')
tool_map = {}
for index, row in tools_df.iterrows():
    try:
        name = row['name']
        object_id = 'tool--' + generate_uuid(name)
        print(f"Processing Tool: {name}")

        platforms = get_platforms(row)  # Use the same helper function for tools
        tool = Tool(
            type='tool',
            id=object_id,
            created=V0_1_RELEASE,
            modified=V0_1_RELEASE,
            created_by_ref=IDENTITY_ID,
            name=name,
            description=row.get('description', ''),
            aliases=safe_split(row.get('aliases', '')),
            external_references=create_external_references(row),
            object_marking_refs=[
                marking_definition.id,
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ],
            allow_custom=True,
            **({'x_mitre_platforms': platforms} if platforms else {})  # Only include if platforms are non-empty
        )

        added_object = add_object(tool)
        if added_object:
            all_objects_for_bundle.append(added_object)
            tool_map[row['external_id']] = tool

    except Exception as e:
        print(f"Error processing row {index} in 'Tool - Tools': {e}")

# Create relationships between Groups and Ransomware or Tools
for _, row in groups_df.iterrows():
    # Handle multiple ransomware entries
    if pd.notna(row['ransomware_used']):
        ransomware_ids = safe_split(row['ransomware_used'])
        for ransomware_id in ransomware_ids:
            try:
                malware = malware_map.get(ransomware_id)
                if not malware:
                    print(f"Malware ID {ransomware_id} not found in malware_map.")
                    continue
                relationship_id = 'relationship--' + generate_uuid(f'uses{row["name"]}{ransomware_id}')

                # Create the new relationship object
                relationship = Relationship(
                    type='relationship',
                    id=relationship_id,
                    created=V0_1_RELEASE,
                    modified=V0_1_RELEASE,
                    created_by_ref=IDENTITY_ID,
                    relationship_type='uses',
                    source_ref='intrusion-set--' + generate_uuid(row['name']),
                    target_ref=malware.id,
                    description=f'The group {row["name"]} uses {malware.name}',
                    object_marking_refs=[
                        marking_definition.id,
                        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
                    ],
                    allow_custom=True
                )

                added_object = add_object(relationship)
                if added_object:
                    all_objects_for_bundle.append(added_object)

            except Exception as e:
                print(f"Error creating relationship for group {row['name']} using ransomware {ransomware_id}: {e}")

    # Handle multiple tool entries
    if pd.notna(row['tools_used']):
        tool_ids = safe_split(row['tools_used'])
        for tool_id in tool_ids:
            try:
                tool = tool_map.get(tool_id)
                if not tool:
                    print(f"Tool ID {tool_id} not found in tool_map.")
                    continue
                relationship_id = 'relationship--' + generate_uuid(f'uses{row["name"]}{tool_id}')

                # Create the new relationship object
                relationship = Relationship(
                    type='relationship',
                    id=relationship_id,
                    created=V0_1_RELEASE,
                    modified=V0_1_RELEASE,
                    created_by_ref=IDENTITY_ID,
                    relationship_type='uses',
                    source_ref='intrusion-set--' + generate_uuid(row['name']),
                    target_ref=tool.id,
                    description=f'The group {row["name"]} uses {tool.name}',
                    object_marking_refs=[
                        marking_definition.id,
                        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
                    ],
                    allow_custom=True
                )

                added_object = add_object(relationship)
                if added_object:
                    all_objects_for_bundle.append(added_object)

            except Exception as e:
                print(f"Error creating relationship for group {row['name']} using tool {tool_id}: {e}")

# Bundle all the processed objects
if all_objects_for_bundle:
    bundle = Bundle(objects=all_objects_for_bundle, allow_custom=True)

    # Save the bundle to a JSON file
    bundle_output_file = f'{output_directory}/ransomware-kb-bundle.json'
    with open(bundle_output_file, 'w') as f:
        f.write(bundle.serialize(pretty=True))

    print(f"Bundle created and saved to {bundle_output_file}")
else:
    print("No objects were processed for the bundle.")

