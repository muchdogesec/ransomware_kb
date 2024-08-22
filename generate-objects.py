import pandas as pd
import uuid
import datetime
import os
import requests
from stix2 import (IntrusionSet, Malware, Tool, Relationship, ExternalReference, FileSystemStore, Bundle, parse)

# Namespace for UUID generation
NAMESPACE_UUID = uuid.UUID('221c1248-e62e-56e5-bbfb-7d5efc477271')
IDENTITY_ID = 'identity--221c1248-e62e-56e5-bbfb-7d5efc477271'

# URLs for the hardcoded STIX objects
MARKING_DEFINITION_URL = 'https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/ransomware_kb.json'
IDENTITY_URL = 'https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/ransomware_kb.json'

# Load the spreadsheet with the correct file path
file_path = 'data/ransomware_kb_master.xlsx'
xl = pd.ExcelFile(file_path)

# Print out sheet names for verification
print("Available sheets:", xl.sheet_names)

# Function to generate consistent UUIDv5
def generate_uuid(name):
    if name is None or not isinstance(name, str) or name.strip() == "":
        raise ValueError(f"The 'name' for UUID generation must be a non-empty string. Invalid value: {name}")
    return str(uuid.uuid5(NAMESPACE_UUID, name.strip()))

# Get the current time
current_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# Function to create an external reference
def create_external_references(row):
    references = []
    for col in row.index:
        if col.startswith('ref.') and pd.notna(row[col]) and isinstance(row[col], str):
            ref_name = col.split('ref.')[-1]
            references.append(ExternalReference(
                source_name=ref_name,
                description=row[col]
            ))
    return references

# Creating a FileSystemStore to hold all the STIX objects
output_directory = './stix2_objects'
os.makedirs(output_directory, exist_ok=True)
fs_store = FileSystemStore(output_directory)

# Function to safely split strings
def safe_split(string, delimiter='\n'):
    if isinstance(string, str):
        return [s.strip() for s in string.split(delimiter) if s.strip()]
    return []

# Function to load an existing object from the store
def load_existing_object(object_id):
    try:
        existing_obj_json = fs_store.get(object_id)
        return parse(existing_obj_json) if existing_obj_json else None
    except Exception:
        return None

# Function to add an object to the store, ensuring correct handling of modified/created times
def add_or_update_object(new_object):
    existing_object = load_existing_object(new_object.id)

    # If the object exists and hasn't changed, do not update the store
    if existing_object and existing_object.serialize() == new_object.serialize():
        return

    # If the object exists and has changed, set the modified time to now, but retain the original created time
    if existing_object:
        new_object = new_object.new_version()
    fs_store.add(new_object)
    return new_object  # Return the object to include it in the bundle

# Download and parse the hardcoded STIX objects
def download_stix_object(url):
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return parse(response.text)

# Importing hardcoded objects
marking_definition = download_stix_object(MARKING_DEFINITION_URL)
identity = download_stix_object(IDENTITY_URL)

# Add the marking definition and identity to the filesystem store
fs_store.add(marking_definition)
fs_store.add(identity)

# Collect these objects for the bundle
all_objects_for_bundle = [marking_definition, identity]

# Process the 'Intrusion Set - Groups' tab
groups_df = xl.parse('Intrusion Set - Groups')
for index, row in groups_df.iterrows():
    try:
        name = row['name']
        object_id = 'intrusion-set--' + generate_uuid(name)
        print(f"Processing Intrusion Set: {name}")  # Debugging line to see what is being processed

        # Create the new object
        intrusion_set = IntrusionSet(
            type='intrusion-set',
            id=object_id,
            created=current_time,
            modified=current_time,
            created_by_ref=IDENTITY_ID,
            name=name,
            description=row.get('description', ''),
            aliases=safe_split(row.get('aliases', '')),
            external_references=create_external_references(row),
            object_marking_refs=[
                marking_definition.id,
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ]
        )

        added_object = add_or_update_object(intrusion_set)
        if added_object:
            all_objects_for_bundle.append(added_object)

    except Exception as e:
        print(f"Error processing row {index} in 'Intrusion Set - Groups': {e}")

# Process the 'Malware - Ransomware' tab
ransomware_df = xl.parse('Malware - Ransomware')
for index, row in ransomware_df.iterrows():
    try:
        name = row['name']
        object_id = 'malware--' + generate_uuid(name)
        print(f"Processing Malware: {name}")  # Debugging line

        platforms = safe_split(row.get('platforms', ''))  # Assuming platforms are in a single column
        malware = Malware(
            type='malware',
            id=object_id,
            created=current_time,
            modified=current_time,
            created_by_ref=IDENTITY_ID,
            name=name,
            description=row.get('description', ''),
            is_family=True,
            aliases=safe_split(row.get('aliases', '')),
            # Including platforms only if they exist
            **({'x_mitre_platforms': platforms} if platforms else {}),
            external_references=create_external_references(row),
            object_marking_refs=[
                marking_definition.id,
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ]
        )

        added_object = add_or_update_object(malware)
        if added_object:
            all_objects_for_bundle.append(added_object)

    except Exception as e:
        print(f"Error processing row {index} in 'Malware - Ransomware': {e}")

# Process the 'Tool - Tools' tab
tools_df = xl.parse('Tool - Tools')
for index, row in tools_df.iterrows():
    try:
        name = row['name']
        object_id = 'tool--' + generate_uuid(name)
        print(f"Processing Tool: {name}")  # Debugging line

        platforms = safe_split(row.get('platforms', ''))  # Assuming platforms are in a single column
        tool = Tool(
            type='tool',
            id=object_id,
            created=current_time,
            modified=current_time,
            created_by_ref=IDENTITY_ID,
            name=name,
            description=row.get('description', ''),
            aliases=safe_split(row.get('aliases', '')),
            # Including platforms only if they exist
            **({'x_mitre_platforms': platforms} if platforms else {}),
            external_references=create_external_references(row),
            object_marking_refs=[
                marking_definition.id,
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ]
        )

        added_object = add_or_update_object(tool)
        if added_object:
            all_objects_for_bundle.append(added_object)

    except Exception as e:
        print(f"Error processing row {index} in 'Tool - Tools': {e}")

# Create relationships between Groups and Ransomware or Tools
for _, row in groups_df.iterrows():
    if pd.notna(row['ransomware_used']):
        try:
            malware_id = 'malware--' + generate_uuid(row['ransomware_used'])
            relationship_id = 'relationship--' + generate_uuid(f'uses{row["name"]}{row["ransomware_used"]}')

            # Create the new relationship object
            relationship = Relationship(
                type='relationship',
                id=relationship_id,
                created=current_time,
                modified=current_time,
                created_by_ref=IDENTITY_ID,
                relationship_type='uses',
                source_ref='intrusion-set--' + generate_uuid(row['name']),
                target_ref=malware_id,
                description=f'The group {row["name"]} uses {row["ransomware_used"]}',
                object_marking_refs=[
                    marking_definition.id,
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
                ]
            )

            added_object = add_or_update_object(relationship)
            if added_object:
                all_objects_for_bundle.append(added_object)

        except Exception as e:
            print(f"Error creating relationship for group {row['name']} using ransomware {row['ransomware_used']}: {e}")

    if pd.notna(row['tools_used']):
        try:
            tool_id = 'tool--' + generate_uuid(row['tools_used'])
            relationship_id = 'relationship--' + generate_uuid(f'uses{row["name"]}{row["tools_used"]}')

            # Create the new relationship object
            relationship = Relationship(
                type='relationship',
                id=relationship_id,
                created=current_time,
                modified=current_time,
                created_by_ref=IDENTITY_ID,
                relationship_type='uses',
                source_ref='intrusion-set--' + generate_uuid(row['name']),
                target_ref=tool_id,
                description=f'The group {row["name"]} uses {row["tools_used"]}',
                object_marking_refs=[
                    marking_definition.id,
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
                ]
            )

            added_object = add_or_update_object(relationship)
            if added_object:
                all_objects_for_bundle.append(added_object)

        except Exception as e:
            print(f"Error creating relationship for group {row['name']} using tool {row['tools_used']}: {e}")

# Create the final STIX bundle with all processed objects, including the imported ones
if all_objects_for_bundle:
    bundle = Bundle(objects=all_objects_for_bundle)

    # Save the bundle to a JSON file
    bundle_output_file = f'{output_directory}/ransomware-kb-bundle.json'
    with open(bundle_output_file, 'w') as f:
        f.write(bundle.serialize(pretty=True))

    print(f"Bundle created and saved to {bundle_output_file}")
else:
    print("No objects were processed for the bundle.")
