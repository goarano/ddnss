import os
import yaml
import secrets
from ipaddress import ip_address

from fastapi import Depends, FastAPI, HTTPException, status, Form, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.logger import logger

from starlette.requests import Request

from pydantic import BaseModel


app = FastAPI()
security = HTTPBasic()


NSS_PATH = os.environ.get('NSS_PATH', 'nss')
CONFIG_FILE = os.environ.get('CONFIG_FILE', 'config.yaml')

METHOD_READ = 'read'
METHOD_WRITE = 'write'


class ReadIpResponse(BaseModel):
    ip: str


class WriteIpResponse(ReadIpResponse):
    old_ip: str = None


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
def get_hostname_ip(hostname):
    return get_hostname_ip_helper(hostname)


@app.put("/{hostname}", dependencies=[Depends(requires_auth)])
def set_hostname_ip(hostname, request: Request, x_forwarded_for: str = Header(None)):
    return set_hostname_ip_helper(hostname, request, x_forwarded_for)


@app.post("/{hostname}", dependencies=[Depends(requires_auth)])
def set_hostname_ip_post(hostname, request: Request, ip: str = Form(None), x_forwarded_for: str = Header(None)):
    return set_hostname_ip_helper(hostname, request, x_forwarded_for, set_ip=ip)


@app.get("/{hostname}/set", dependencies=[Depends(requires_auth)])
@app.put("/{hostname}/set", dependencies=[Depends(requires_auth)])
def set_hostname_ip_compat(hostname, request: Request, x_forwarded_for: str = Header(None)):
    return set_hostname_ip_helper(hostname, request, x_forwarded_for)


@app.post("/{hostname}/set", dependencies=[Depends(requires_auth)])
def set_hostname_ip_compat_post(hostname, request: Request, ip: str = Form(None), x_forwarded_for: str = Header(None)):
    return set_hostname_ip_helper(hostname, request, x_forwarded_for, set_ip=ip)


def get_hostname_ip_helper(hostname):
    ip = get_ip(hostname)
    if ip:
        return ReadIpResponse(ip=ip)
    raise HTTPException(status_code=404, detail="No IP saved")


def set_hostname_ip_helper(hostname, request, x_forwarded_for, set_ip=None):
    ip = x_forwarded_for
    if set_ip:
        ip = set_ip
    else:
        ip = ip_from_request(request, x_forwarded_for)
    try:
        ip_address(ip)  # validate ip address
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid IP {ip}")

    old_ip = get_ip(hostname)
    if old_ip != ip:
        write_ip(hostname, ip)
    return WriteIpResponse(ip=ip, old_ip=old_ip)


def ip_from_request(request, x_forwarded_for):
    if x_forwarded_for:
        return x_forwarded_for
    return request.client.host


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
