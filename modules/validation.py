import re


# in this table you should record any types and regular expressions for validation
validation_data = {
    "email": r'^\S+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
    "password": r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$',
    "phone": r'^[0-9]+$',
    "userID": r'^[0-9]+$',
    "confirm_token": r'^[a-z0-9]{128}$',
    'pin': r'^\d+$'
     }


def isvalid(validation_type, item):
    if not re.search(validation_data[validation_type], item):
        return False
    return True


# for many items with one type of data
def arevalid(validation_type, items):
    result = True
    for item in items:
        if not re.search(validation_data[validation_type], item):
            result = False
    return result


# For big JSON data
def isvalid_json(item):
    result = True
    for key in item.keys():
        result = result and bool(re.search(validation_data[key], item[key]))
    return result

