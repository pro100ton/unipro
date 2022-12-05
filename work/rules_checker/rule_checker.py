from dotenv import load_dotenv

INVALID_FIELDS_LIST = [
    "EventFirst",
    "EventLast",
    "EventCount",
    "EventTimestamp",
    "EventSeverity",
    "EventSrcMsg",
    "DeviceVendor",
    "DeviceProduct",
    "DeviceVersion",
    "DeviceAction",
    "SignId",
    "SignCategory",
    "SignSubcategory",
    "SignName",
    "SourceIp",
    "SourceMac",
    "SourceHost",
    "SourcePort",
    "SourceUser",
    "DestinationIp",
    "DestinationIp",
    "DestinationHost",
    "DestinationPort",
    "DestinationUser",
]

def check_correlation_rules_template_language(rules_file):
    f = open(rules_file)
    rules_string = f.read()
    error_count = 0
    for entry in INVALID_FIELDS_LIST:
        if entry in rules_string:
            print(f"{entry}:TRUE")
            error_count += 1
        else:
            print(f"${entry}:FALSE")
    return error_count
