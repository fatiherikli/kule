""" krest 0.22:

      A kule based, SSL enabled, read-only rest interface for a configuration
      management schema on top of MongoDB.  The assumed layout for krest to
      be able to read configuration data is this: you must have a database
      called "config", and inside "config", you have collections for each
      environment (i.e. "prod", "test", and "dev").  Inside each collection,
      each document must have at least the keys "app" and "config", or in
      otherwords should fit the following schema:

        {'app':app_name, 'config': <arbitrary configuration json> }

      In order to retrieve configuration for an app "app" in the environment
      "prod", retrieve json from a url like this:

        https://LISTEN_HOST:LISTEN_PORT/test/app?key=<PASSWORD>

      Inside the same directory as this file, you need 3 other files: first,
      a plaintext file "krest.pass" which contains the main password for this
      server, second a ssl cert "krest_cert.pem", and third a private key file
      "krest_key.pem".

      The files can be generated as follows:

        1. openssl genrsa -out krest_key.pem 1024
        2. openssl req -new -x509 -key krest_key.pem -out krest_cert.pem -days 1095
        3. echo "mypass" > krest.pass

      System requirements:
        openssl, maybe libffi-dev

      Python requirements:
        kule==0.3, CherryPy==3.2.4

      Credits:
        SSL is based on the recipe here:
          https://github.com/nickbabcock/bottle-ssl
"""
import os
from bottle import error, request, abort, ServerAdapter

from cherrypy import wsgiserver
from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter

from kule import Kule
from kule.helpers import jsonify

LISTEN_PORT = 8000
LISTEN_HOST = "0.0.0.0"

PASSWORD_FILE = os.path.join(os.path.dirname(__file__), 'krest.pass')
MASTER_PASS = open(PASSWORD_FILE).read().strip()

CERT_FILE = os.path.join(os.path.dirname(__file__), 'krest_cert.pem')
PEM_FILE = os.path.join(os.path.dirname(__file__), 'krest_key.pem')

@error(404)
def error404(error=None):
    """ standard error messages should still return json """
    return jsonify(dict(error=404, text=error or 'Nothing here'))

@error(401)
def error401(error=None):
    """ standard error messages should still be json """
    return jsonify(dict(error=401, text='Unauthorized'))

def check_auth(fxn):
    """ wraps a function so that auth will run before that fxn """
    def newf(*args, **kargs):
        if request.GET.get('key', None) == MASTER_PASS:
            return fxn(*args, **kargs)
        else:
            return error401()
    return newf


class ReadOnly(Kule):
    """ this class removes the write capabilities of the default Kule server"""

    def patch_detail(self, collection, pk):
        return abort(code=500, text='not implemented')
    put_detail = delete_detail = post_list = patch_detail


class Krest(ReadOnly):
    """ Reader for mongod-based CM schema.
        Every collection-name is considered an environment,
        and underneath it JSON must have an "app" key, where the value
        is an application-name.  Everything else in the JSON is considered
        configuration for that application.  Example follows

        MongoDB:
            collection: "test"
                item: {app:my_first_application, app_var_name:value, .. }
                item: {app:my_other_application, app_var_name:value, .. }
            collection: "prod"
                item: {app:my_first_application, app_var_name:value, .. }
                item: {app:my_other_application, app_var_name:value, .. }
    """
    def __init__(self):
        super(Krest, self).__init__(
            database='config', collections=['dev', 'test', 'prod'])

    def get_collection(self, collection):
        """Returns the given collection if it permitted"""
        if self.collections and collection not in self.collections:
            error404('invalid environment')
        return self.connection[collection]

    @check_auth
    def get_list(self, collection):
        """Returns a list of app names """
        env_name = collection
        collection = self.get_collection(env_name)
        collection = collection.find({})
        return jsonify( [ x.get('app', x['_id' ] ) for x in collection])

    @check_auth
    def get_detail(self, collection, pk):
        """ Returns a single application's
            configuration for the given environment
        """
        app_name = pk
        env_name = collection
        collection = self.get_collection(env_name)
        data = collection.find_one({"app": app_name}) or {}
        data = data.copy()
        data.pop('_id', None)
        data.update(env=env_name)
        if data:
            return jsonify(data)
        else:
            return jsonify({})


class SSLCherryPyServer(ServerAdapter):
    """ Create our own sub-class of Bottle's ServerAdapter
        so that we can specify SSL. Using just server='cherrypy'
        uses the default cherrypy server, which doesn't use SSL
    """
    def run(self, handler):
        server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)
        server.ssl_adapter = pyOpenSSLAdapter(CERT_FILE, PEM_FILE)
        try:
            server.start()
        finally:
            server.stop()

if __name__=='__main__':
    if not os.path.exists(CERT_FILE):
        raise RuntimeError("no such cert: {0}".format(CERT_FILE))
    if not os.path.exists(PEM_FILE):
        raise RuntimeError("no such cert: {0}".format(PEM_FILE))
    krest = Krest()
    krest.run(host=LISTEN_HOST, port=LISTEN_PORT, server=SSLCherryPyServer)
