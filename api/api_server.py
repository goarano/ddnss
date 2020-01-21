import os
import yaml
from flask import Flask, request, Response
from functools import wraps
from ipaddress import ip_address

app = Flask(__name__)

NSS_PATH = os.environ.get('NSS_PATH', 'nss')
CONFIG_FILE = os.environ.get('CONFIG_FILE', 'config.yaml')

METHOD_READ = 'read'
METHOD_WRITE = 'write'


def check_auth(hostname, username, password, method):
    """This function is called to check if a username /
    password combination is valid.
    """
    app.logger.debug(f'{method} {hostname} as {username}')
    app.logger.debug(f'{USERS} {AUTH}')
    hostname = sanitize_hostname(hostname)
    domains = hostname.split('.')
    try:
        if not USERS[username] == password:
            return False
        for i in range(len(domains)):
            subdomain = '.'.join(domains[i:])
            cfg = AUTH.get(subdomain)
            if cfg:
                if method in ('POST', 'PUT') and username in cfg.get(METHOD_WRITE):
                    return True
                if method == 'GET' and (username in cfg.get(METHOD_WRITE) or username in cfg.get(METHOD_READ)):
                    return True
        return False
    except KeyError:
        return False


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        method = request.method
        if not auth or not check_auth(kwargs.get('hostname'), auth.username, auth.password, method):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


@app.route("/<hostname>", methods=['GET', 'PUT'])
@requires_auth
def endpoint(hostname):
    if request.method == 'GET':
        ip = get_ip(hostname)
        if ip:
            return ip
        else:
            return "no saved IP"
    elif request.method == 'PUT':
        ip = retrieve_ip()
        write_ip(hostname, ip)
        return "wrote " + ip


# legacy support
@app.route("/<hostname>/PUT")
@app.route("/<hostname>/set", methods=['GET', 'POST', 'PUT'])
@requires_auth
def endpoint_put(hostname):
    ip = retrieve_ip()
    old_ip = get_ip(hostname)
    write_ip(hostname, ip)
    if old_ip and old_ip != ip:
        return "replaced " + old_ip + " with " + ip
    return "wrote " + ip


def retrieve_ip():
    try:
        ip = request.values.get('ip').strip()
        ip_address(ip)  # validate ip address
        return ip
    except:
        return request.environ.get('HTTP_X_REAL_IP', request.remote_addr)


def sanitize_hostname(hostname):
    if hostname[-1] == '.':
        return hostname[0:-1]
    return hostname


def get_ip(hostname):
    hostname = sanitize_hostname(hostname)
    try:
        with open(get_file_path(hostname), 'r') as host_file:
            ip = host_file.read()
        ip = ip.strip()
        return ip
    except FileNotFoundError:
        return None


def write_ip(hostname, ip):
    hostname = sanitize_hostname(hostname)
    with open(get_file_path(hostname), 'w') as host_file:
        host_file.write(ip)


def get_file_path(hostname):
    return f'{NSS_PATH}/{hostname}'


def init(app):
    with open(CONFIG_FILE, 'r') as stream:
        cfg = yaml.safe_load(stream)
        return cfg.get('users'), cfg.get('auth')


USERS, AUTH = init(app)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
