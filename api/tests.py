import api_server as a


def setup_function(function):
    """ setup any state tied to the execution of the given function.
    Invoked for every test function in the module.
    """
    a.CONFIG_FILE = 'config.example.yaml'
    a.USERS, a.AUTH = a.init(a.app)


def test_check_auth(monkeypatch):
    # login
    assert a.check_auth('ddnss', 'user', 'password', 'GET') is False
    assert a.check_auth('ddnss', 'admin', 'password', 'GET') is False
    # read
    assert a.check_auth('ddnss', 'admin', 'secret', 'GET') is True
    assert a.check_auth('ddnss', 'dns', 'secret', 'GET') is True
    # subdomain
    assert a.check_auth('test.ddnss', 'admin', 'secret', 'GET') is True
    assert a.check_auth('test.ddnss', 'dns', 'secret', 'GET') is True
    assert a.check_auth('ddnss.test', 'admin', 'secret', 'GET') is False
    assert a.check_auth('ddnss.test', 'dns', 'secret', 'GET') is False
    # write
    assert a.check_auth('ddnss', 'admin', 'secret', 'PUT') is True
    assert a.check_auth('ddnss', 'dns', 'secret', 'PUT') is False
