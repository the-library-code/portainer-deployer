from datetime import datetime as dt
from hashlib import sha256
from yaml import Loader, load, dump, YAMLError
from re import match
from typing import Any
from os import path, access, W_OK, R_OK
import logging


def format_resource(resource: dict):
    """
    Return a simple tuple with resource and resource control ID, from the example response dict:
    {
    "ID": "z97bz5hrdk0ex7j44gcxzrvyj",
    "Portainer": {
        "ResourceControl": {
            "Id": 15,
            "ResourceId": "z97bz5hrdk0ex7j44gcxzrvyj",
            "SubResourceIds": [],
            "Type": 5,
            "UserAccesses": [
                {
                    "UserId": 2,
                    "AccessLevel": 1
                }
            ],
            "TeamAccesses": [],
            "Public": false,
            "AdministratorsOnly": false,
            "System": false
        }
    }
}
    :param resource: The resource to format
    :return: formatted resource
    """
    if len(resource) == 0:
        return ()
    formatted_resource = dict()
    if 'Portainer' in resource and 'ResourceControl' in resource['Portainer']:
        if 'ID' in resource:
            name = resource['ID']
        elif 'Id' in resource:
            name = resource['Id']
        elif 'Name' in resource:
            name = resource['Name']
        else:
            raise Exception("Error formatting resource")
        formatted_resource = (name, resource['Portainer']['ResourceControl']['Id'])
    return formatted_resource


def format_stack_info_generator(stacks: list):
    """Format the list of stacks from Portainer and return a generator with it.

    Args:
        stacks (list): Raw list of stacks from Portainer.
    
    Yields:
        tuple: Tuple of some stack info values.
    """    
    for stack in stacks:
        stack_info = (
            stack['Id'], 
            stack['EndpointId'], 
            stack['Name'], 
            f"{dt.fromtimestamp(stack['CreationDate']).strftime('%m-%d-%y %H:%m')} by {stack['CreatedBy']}",
            f"{dt.fromtimestamp(stack['UpdateDate']).strftime('%m-%d-%y %H:%m')} by {stack['UpdatedBy']}"
        )
        yield stack_info


def format_stack_info(stack: dict):
    """Format the stack info from Portainer.

    Args:
        stack (dict): Raw stack info from Portainer.
    
    Returns:
        tuple: Tuple of some stack info values.
    """
    if len(stack) == 0:
        return ()

    return (
        stack['Id'], 
        stack['EndpointId'], 
        stack['Name'], 
        f"{dt.fromtimestamp(stack['CreationDate']).strftime('%m-%d-%y %H:%m')} by {stack['CreatedBy']}",
        f"{dt.fromtimestamp(stack['UpdateDate']).strftime('%m-%d-%y %H:%m')} by {stack['UpdatedBy']}"
    )


def generate_random_hash() -> str:
    """Generate a pseudo-random hash.

    Returns:
        str: Random hash.
    """    
    random_hash = sha256(str(dt.now()).encode('utf-8')).hexdigest()
    return random_hash


def recursive_dict(dictionary: dict, keys: list, new_value: Any=None) -> dict:
    """Recursively set a value in a dictionary.

    Args:
        dictionary (dict): Target dictionary.
        keys (list): Keys to access the value.
        new_value (Any, optional): Value to be set. Defaults to None.

    Returns:
        dict: _description_
    """    
    if len(keys) == 1:
        if type(new_value) == str:
            truly_boolean = {
                'true': True,
                'True': True,
                'false': False,
                'False': False
            }
            dictionary[keys[0]] = truly_boolean.get(new_value, new_value)

        else:
            dictionary[keys[0]] = new_value
    
    elif not dictionary:
        dictionary[keys[0]] = recursive_dict({keys[1]: {}}, keys[1:], new_value)
    
    else:
        dictionary[keys[0]] = recursive_dict(dictionary.get(keys[0], {}), keys[1:], new_value)

    return dictionary


def edit_yml_file(path: str, key_group:str, new_value: Any) -> None:
    """Edit a yaml file base in a chain of keys in dot notation. i.e. 'a.b.c'

    Args:
        path (str): Path to the yaml file.
        keys (str): Keys in dot notation. 
        new_value (Any): New value to be set for the last key in the keys.
    """    
    data = {}
    keys = key_group.split('.')
    
    try:
        with open(path, 'r') as f:
            data = load(f, Loader=Loader)
        
        with open(path, 'w') as f:    
            try:
                if not data:
                    data = dict()        
                recursive_dict(data, keys, new_value)
            
            except KeyError:
                return f"Wrong key secuence {keys}, not found in {path}."

            dump(data, f) 
    
    except FileNotFoundError:
        return f"File {path} not found."


def validate_key_value(pair: str) -> bool:
    """Validate a key=value pair, where key is in dot notation. i.e. a.b.c=value1 d=value2.
    This validation is for a list of values as well. i.e. a.b.c='[val1,val2,val3]' d='[1,2,a,c]'.

    Args:
        pair (str): A key=value pair.

    Returns:
        bool: True if the pair is valid, False otherwise.
    """    
    # Attempts to validate normal key=value format
    if match(r'^[a-zA-Z0-9-_\.]+=[^\[\]]+$', pair):
        return True

    # Attempts to validate list of values format
    elif match(r'^[a-zA-Z0-9-_\.]+=\[[^\]]*]+$', pair):
        return True

    return False


def validate_yaml(path: str = None, data: str = None) -> bool:
    """Validate a yaml file.

    Args:
        path (str, optional): Path to the yaml file. Defaults to None.
        data (str, optional): Data to be validated in case path is not set. Defaults to None.

    Returns:
        bool: True if is valid, False otherwise.
    """    
    try:
        if path:
            with open(path, 'r') as f:
                load(f, Loader=Loader)
            return True
        
        elif data:
            load(data, Loader=Loader)
            return True

        else:
            return False
        
    except YAMLError:
        return False
    except FileNotFoundError:
        return False


def generate_response(message: str, details: str=None, status: bool=False, code: int = None) -> dict:
    """Generate a response to be returned to the client.
    
    Args:
        message (str): Message to be returned.
        details (str, optional): Details to be returned. Defaults to None.
        status (bool, optional): Status of the response. Defaults to False.
        code (int, optional): HTTP code of the response. Defaults to None.
    """
    return {
        'message': message,
        'details': details if details else message,
        'status': status,
        'code': code
    }


def update_config_dir(path_to_file: str, verify: bool = True):
    """Update the config dir.

    Args:
        path (str): Path to the config dir.
        strict (bool, optional): If True, the path existence and accessibility will be verified before update path. Defaults to True.
    """    
    try:
        file_abs_path = path.abspath(path.dirname(__file__))
        env_path = path.join(file_abs_path, '../.env')

        if not verify:
            with open(env_path, 'w') as f:
                f.write('[CONFIG]\n')
                f.write(f'PATH_TO_CONFIG={path_to_file}\n')
            
            return

        # Confirm path exists and is a directory
        if path.exists(path_to_file) and path.isfile(path_to_file):
            if access(path_to_file, R_OK) and access(path_to_file, W_OK):
                with open(env_path, 'w') as f:
                    f.write('[CONFIG]\n')
                    f.write(f'PATH_TO_CONFIG={path_to_file}\n')
            else:
                raise PermissionError

        else:
            raise FileNotFoundError 

    except FileNotFoundError:
        return f"File {path_to_file} not found or it could not be a file."	
    except PermissionError:
        return f"Permission denied to {path_to_file}, make sure it is writable and readable by App User."
    except Exception as e:
        return f"Error: {e}"

def request_confirmation(msg: str) -> bool:
    while True:
        print(msg)
        choice = input(f"Confirm with [Y/n]: ").lower()
        if match(r'^(?:y(?:es)?)$', choice):
            return True
        if match(r'^(?:n(?:o)?)$', choice):
            return False


# ==================== Logger Formatter ====================
class CustomFormatter(logging.Formatter):
    """Custom formatter to format the log messages."""
    
    @property
    def formats(self):
        grey = "\x1b[38;20m"
        yellow = "\x1b[33;20m"
        red = "\x1b[31;20m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

        FORMATS = {
            logging.DEBUG: grey + format + reset,
            logging.INFO: grey + format + reset,
            logging.WARNING: yellow + format + reset,
            logging.ERROR: red + format + reset,
            logging.CRITICAL: bold_red + format + reset
        }

        return FORMATS

    def format(self, record) -> logging.Formatter:
        log_fmt = self.formats.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class StdoutFormatter(CustomFormatter):
    """Custom formatter to format the log messages to print in ."""
    
    @property
    def formats(self):
        grey = "\x1b[38;20m"
        yellow = "\x1b[33;20m"
        red = "\x1b[31;20m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        format = "%(levelname)s - %(message)s"

        FORMATS = {
            logging.DEBUG: grey + format + reset,
            logging.INFO: grey + format + reset,
            logging.WARNING: yellow + format + reset,
            logging.ERROR: red + format + reset,
            logging.CRITICAL: bold_red + format + reset
        }

        return FORMATS


class FormatterDispatcher:
    def __init__(self, formatters: dict):
        self._formatters = formatters

    def format(self, record) -> logging.Formatter:
        formatter = self._formatters.get(record.name)
        return formatter.format(record)


custom_handler = logging.StreamHandler()

formatters = {
    'stdout': StdoutFormatter(),
    'file': CustomFormatter(),
    'dev': CustomFormatter()
}

custom_handler.setFormatter(FormatterDispatcher(formatters))

for logger_name in formatters:
    logging.getLogger(logger_name).setLevel(logging.DEBUG)

logging.getLogger().addHandler(custom_handler)
