from flask import Flask, request, Response
from functools import wraps

AUTH = {
        'host': {
            'username': 'admin',
            'password': 'secret'
            }
        }

CONFIG = {
        'NSS_PATH': 'nss/'
        }

def check_auth(hostname, username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    auth = AUTH.get(hostname)
    if auth == None:
        return False
    return auth.get('username') == username and auth.get('password') == password

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
        if not auth or not check_auth(kwargs.get('hostname'), auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__)

@app.route("/<hostname>", methods=['GET', 'PUT'])
@requires_auth
def hello(hostname):
    if request.method == 'GET':
        ip = get_ip(hostname)
        return "read " + ip
    elif request.method == 'PUT':
        ip = request.remote_addr
        write_ip(hostname, ip)
        return "wrote " + ip

def get_ip(hostname):
    with open(CONFIG['NSS_PATH']+'/'+hostname, 'r') as host_file:
        ip = host_file.read()
    ip = ip.strip()
    return ip

def write_ip(hostname, ip):
    with open(CONFIG['NSS_PATH']+'/'+hostname, 'w') as host_file:
        ip = host_file.write(ip)

if __name__ == "__main__":
    app.run()

