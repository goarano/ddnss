from flask import Flask, request, Response
from functools import wraps

AUTH = {
        'host': {
            'username': 'admin',
            'password': 'secret'
            }
        }

def check_auth(hostname, username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    auth = AUTH.get(hostname)
    if auth == None:
        return False
    print(auth.get('username'), auth.get('password'))
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
        print(kwargs.get('hostname'))
        auth = request.authorization
        if not auth or not check_auth(kwargs.get('hostname'), auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__)

@app.route("/<hostname>")
@requires_auth
def hello(hostname):
    return "Hello World!"

if __name__ == "__main__":
    app.run()

