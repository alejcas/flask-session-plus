from flask.sessions import SessionInterface as FlaskSessionInterface
from flask_session_plus.backends import SecureCookieSessionInterface, FirestoreSessionInterface
from flask_session_plus.core import MultiSession


class MultiSessionInterface(FlaskSessionInterface):

    def __init__(self, sessions_config):
        self.session_interfaces = []
        for session_conf in sessions_config:
            session_fields = session_conf.get('session_fields')
            session_type = session_conf.pop('session_type')
            if session_type == 'secure_cookie':
                self.session_interfaces.append((SecureCookieSessionInterface(**session_conf), session_fields))
            elif session_type == 'firestore':
                self.session_interfaces.append((FirestoreSessionInterface(**session_conf), session_fields))

    @staticmethod
    def get_session_for(session_interface, session, session_fields):
        """ Returns all the sessions configured """
        if len(session_fields) == 0:
            return session
            # # all the fields are forward to the interface
            # for key, value in session.items():
            #     new_dict[key] = value
        else:
            new_dict = {}
            modified = False
            for field in session_fields:
                value = session.get(field)
                new_dict[field] = value
                modified = modified or field in session.tracked_status
            new_session = session_interface.session_class(new_dict)
            new_session.modified = modified
            return new_session

    def open_session(self, app, request):
        """ Opens all the inner session interfaces and integrates all the sessions into one """
        common_dict = {}
        session_sids = {}
        for si, _ in self.session_interfaces:
            session = si.open_session(app, request)
            # 1st: update dict values
            common_dict.update(dict(session))
            # 2nd: integrate session sid if available
            session_sids[si.cookie_name] = session.get_sid(si.cookie_name)
        multi_session = MultiSession(common_dict)
        multi_session.sid = common_dict
        return multi_session

    def save_session(self, app, session, response):
        """ Saves all session info into each of the session interfaces """
        for si, session_fields in self.session_interfaces:
            interface_session = self.get_session_for(si, session, session_fields)
            si.save_session(app, interface_session, response)


class Session(object):

    session_types = {
        'secure_cookie': ''
    }

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.session_interface = self.create_session_interface(app)

    def create_session_interface(self, app):
        # Config vars:

        # From flask session:
        # SESSION_COOKIE_NAME
        # SESSION_COOKIE_DOMAIN
        # SESSION_COOKIE_PATH
        # SESSION_COOKIE_HTTPONLY
        # SESSION_COOKIE_SECURE
        # PERMANENT_SESSION_LIFETIME

        # From Flask Session:
        # SESSION_TYPE
        # SESSION_PERMANENT
        # SESSION_USE_SIGNER
        # SESSION_KEY_PREFIX
        # SESSION_REDIS
        # SESSION_MEMCACHED
        # SESSION_FILE_DIR
        # SESSION_FILE_THRESHOLD
        # SESSION_FILE_MODE
        # SESSION_MONGODB
        # SESSION_MONGODB_DB
        # SESSION_MONGODB_COLLECT
        # SESSION_SQLALCHEMY
        # SESSION_SQLALCHEMY_TABLE

        sessions_config = app.config.get('SESSION_CONFIG', [])
        if not sessions_config:
            # add the default session
            sessions_config.append({
                'cookie_name': app.config.get('SESSION_COOKIE_NAME'),
                'cookie_domain': app.config.get('SESSION_COOKIE_DOMAIN'),
                'cookie_path': app.config.get('SESSION_COOKIE_PATH'),
                'cookie_httponly': app.config.get('SESSION_COOKIE_HTTPONLY'),
                'cookie_secure': app.config.get('SESSION_COOKIE_SECURE'),
                'cookie_lifetime': app.config.get('PERMANENT_SESSION_LIFETIME'),
            })

        for session in sessions_config:
            if not session.get('cookie_name'):
                raise ValueError('Each session configuration must define a cookie name')
            session.setdefault('session_type', 'secure_cookie')  # the session Interface to be used
            session.setdefault('session_fields', [])  # the list of fields used for this session

        return MultiSessionInterface(sessions_config)
