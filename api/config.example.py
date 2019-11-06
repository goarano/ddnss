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
