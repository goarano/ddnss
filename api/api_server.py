import os
import yaml
import secrets
from ipaddress import ip_address

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.logger import logger

from starlette.requests import Request


app = FastAPI()
security = HTTPBasic()


NSS_PATH = os.environ.get('NSS_PATH', 'nss')
CONFIG_FILE = os.environ.get('CONFIG_FILE', 'config.yaml')

METHOD_READ = 'read'
METHOD_WRITE = 'write'


def check_auth(hostname, username, password, method):
    """This function is called to check if a username /
    password combination is valid.
    """
    logger.debug(f'{method} {hostname} as {username}')
    logger.debug(f'{USERS} {AUTH}')
    hostname = sanitize_hostname(hostname)
    domains = hostname.split('.')
    try:
        if not secrets.compare_digest(USERS[username], password):
            unauthorized()
        for i in range(len(domains)):
            subdomain = '.'.join(domains[i:])
            cfg = AUTH.get(subdomain)
            if cfg:
                if method in ('POST', 'PUT') and username in cfg.get(METHOD_WRITE):
                    return True
                if method == 'GET' and (username in cfg.get(METHOD_WRITE) or username in cfg.get(METHOD_READ)):
                    return True
        unauthorized()
    except KeyError:
        unauthorized()


def unauthorized():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Basic"},
    )


def requires_auth(hostname: str, request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    method = request.method
    check_auth(hostname, credentials.username, credentials.password, method)


@app.get("/{hostname}", dependencies=[Depends(requires_auth)])
@app.put("/{hostname}", dependencies=[Depends(requires_auth)])
def endpoint(hostname, request: Request):
    if request.method == 'GET':
        ip = get_ip(hostname)
        if ip:
            return ip
        else:
            return "no saved IP"
    elif request.method == 'PUT':
        ip = retrieve_ip(request)
        write_ip(hostname, ip)
        return "wrote " + ip


@app.get("/{hostname}/set", dependencies=[Depends(requires_auth)])
@app.post("/{hostname}/set", dependencies=[Depends(requires_auth)])
@app.put("/{hostname}/set", dependencies=[Depends(requires_auth)])
def endpoint_put(hostname, request: Request):
    ip = retrieve_ip(request)
    old_ip = get_ip(hostname)
    write_ip(hostname, ip)
    if old_ip and old_ip != ip:
        return "replaced " + old_ip + " with " + ip
    return "wrote " + ip


def retrieve_ip(request):
    if 'HTTP_X_REAL_IP' in request.headers:
        ip = request.headers.get('HTTP_X_REAL_IP')
    else:
        ip = request.client.host
    ip_address(ip)  # validate ip address
    return ip


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
