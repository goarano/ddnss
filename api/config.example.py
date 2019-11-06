USERS = {
    'admin': 'secret',
    'dns': 'secret',
}

AUTH = {
    'ddnss': {
        'read': ['dns'],
        'write': ['admin']
    }
}

CONFIG = {
        'NSS_PATH': 'nss/'
        }
