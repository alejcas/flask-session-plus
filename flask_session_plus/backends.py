import logging
from datetime import datetime, timedelta
from uuid import uuid4
import hashlib

from flask.helpers import total_seconds
from flask.json.tag import TaggedJSONSerializer
from pytz import utc
from flask.sessions import SessionInterface as FlaskSessionInterface
from itsdangerous import BadSignature, want_bytes, Signer, URLSafeTimedSerializer
from flask_session_plus.core import MultiSession

log = logging.getLogger(__name__)


class BaseSessionInterface(FlaskSessionInterface):
    """ Base Session Interface """

    def __init__(self, cookie_name, cookie_max_age=None, cookie_domain=None,
                 cookie_path=None, cookie_httponly=True, cookie_secure=False,
                 cookie_samesite=None, session_lifetime=None,
                 refresh_on_request=True, **kwargs):
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.cookie_domain = cookie_domain
        self.cookie_path = cookie_path
        self.cookie_httponly = cookie_httponly
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.session_lifetime = session_lifetime or timedelta(days=1)
        self.refresh_on_request = refresh_on_request

    def get_expiration_time(self, app, session):
        """A helper method that returns an expiration date for the session
        or ``None`` if the session is linked to the browser session.  The
        default implementation returns now + the permanent session
        lifetime configured on the application.
        """
        if session.is_permanent(self.cookie_name):
            return datetime.utcnow() + timedelta(days=31)
        else:
            return datetime.utcnow() + self.session_lifetime

    def should_set_cookie(self, app, session):
        """Used by session backends to determine if a ``Set-Cookie`` header
        should be set for this session cookie for this response. If the session
        has been modified, the cookie is set. If the session is permanent and
        the ``SESSION_REFRESH_EACH_REQUEST`` config is true, the cookie is
        always set.

        This check is usually skipped if the session was deleted.

        .. versionadded:: 0.11
        """
        return session.modified or self.refresh_on_request or app.config['SESSION_REFRESH_EACH_REQUEST']

    def open_session(self, app, request):
        raise NotImplementedError

    def save_session(self, app, session, response):
        raise NotImplementedError


session_json_serializer = TaggedJSONSerializer()


class SecureCookieSessionInterface(BaseSessionInterface):
    """ A Secure Cookie Session Interface that works with Flask-Multi-Session """

    #: the salt that should be applied on top of the secret key for the
    #: signing of cookie based sessions.
    salt = 'cookie-session'
    #: the hash function to use for the signature.  The default is sha1
    digest_method = staticmethod(hashlib.sha3_256)
    #: the name of the itsdangerous supported key derivation.  The default
    #: is hmac.
    key_derivation = 'hmac'
    #: A python serializer for the payload.  The default is a compact
    #: JSON derived serializer with support for some extra Python types
    #: such as datetime objects or tuples.
    serializer = session_json_serializer
    session_class = MultiSession

    def get_expiration_time(self, app, session):
        """A helper method that returns an expiration date for the session
        or ``None`` if the session is linked to the browser session.  The
        default implementation returns now + the permanent session
        lifetime configured on the application.
        """
        if session.is_permanent(self.cookie_name):
            return datetime.utcnow() + timedelta(days=31)
        else:
            if self.cookie_max_age is not None:
                return datetime.utcnow() + timedelta(seconds=self.cookie_max_age)
            else:
                return None

    def get_signing_serializer(self, app):
        if not app.secret_key:
            return None
        signer_kwargs = dict(
            key_derivation=self.key_derivation,
            digest_method=self.digest_method
        )
        return URLSafeTimedSerializer(app.secret_key, salt=self.salt,
                                      serializer=self.serializer,
                                      signer_kwargs=signer_kwargs)

    def open_session(self, app, request):
        s = self.get_signing_serializer(app)
        if s is None:
            return None
        val = request.cookies.get(self.cookie_name)
        if not val:
            return self.session_class()
        max_age = self.cookie_max_age or None

        try:
            data = s.loads(val, max_age=max_age)
            return self.session_class(data)
        except BadSignature:
            return self.session_class()

    def save_session(self, app, session, response):
        if self.cookie_domain is not None:
            domain = self.cookie_domain if self.cookie_domain else self.get_cookie_domain(app)
        else:
            domain = self.get_cookie_domain(app)

        path = self.cookie_path or self.get_cookie_path(app)

        # If the session is modified to be empty, remove the cookie.
        # If the session is empty, return without setting the cookie.
        if not session:
            if session.modified:
                response.delete_cookie(
                    self.cookie_name,
                    domain=domain,
                    path=path
                )

            return

        # Add a "Vary: Cookie" header if the session was accessed at all.
        if session.accessed:
            response.vary.add('Cookie')

        if not self.should_set_cookie(app, session):
            return

        httponly = self.cookie_httponly or self.get_cookie_httponly(app)
        secure = self.cookie_secure or self.get_cookie_secure(app)
        samesite = self.cookie_samesite or self.get_cookie_samesite(app)
        expires = self.get_expiration_time(app, session)
        val = self.get_signing_serializer(app).dumps(dict(session))
        response.set_cookie(
            self.cookie_name,
            val,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite
        )


class BackendSessionInterface(BaseSessionInterface):
    """ A common Session Interface for all backend Interfaces """

    session_class = MultiSession

    def _generate_sid(self):
        return str(uuid4())

    def _get_signer(self, app):
        if not app.secret_key:
            return None
        return Signer(app.secret_key, salt='flask-session',
                      key_derivation='hmac')

    def open_session(self, app, request):
        raise NotImplementedError

    def save_session(self, app, session, response):
        raise NotImplementedError


class FirestoreSessionInterface(BackendSessionInterface):
    """ A Session interface that uses Google Cloud Firestore as backend. """

    # serializer = session_json_serializer

    def __init__(self, client, collection, key_prefix='session', use_signer=False, **kwargs):
        """
        :param client: A ``firestore.Client`` instance.
        :param collection: The collection you want to use.
        :param key_prefix: A prefix that is added to all Firestore store keys.
        :param use_signer: Whether to sign the session id cookie or not.
        :param kwargs: extra params to the base class
        """
        if 'session_lifetime' not in kwargs:
            kwargs['session_lifetime'] = timedelta(days=1)  # by default the session lasts 1 day.
        super(FirestoreSessionInterface, self).__init__(**kwargs)
        if client is None:
            from google.cloud import firestore
            client = firestore.Client()
        self.client = client
        self.store = client.collection(collection)
        self.key_prefix = key_prefix
        self.use_signer = use_signer

    def _delete_session_from_store(self, store_id):
        """ Deletes the session from the store """
        try:
            self.store.document(store_id).delete()
        except Exception as e:
            log.error(f'Error while deleting expired session (session id: {store_id}): {e}')
            return False
        return True

    def open_session(self, app, request):
        sid = request.cookies.get(self.cookie_name)
        if not sid:
            sid = self._generate_sid()
            return self.session_class(sid={self.cookie_name: sid})
        if self.use_signer:
            signer = self._get_signer(app)
            if signer is None:
                return None
            try:
                sid_as_bytes = signer.unsign(sid)
                sid = sid_as_bytes.decode()
            except BadSignature:
                sid = self._generate_sid()
                return self.session_class(sid={self.cookie_name: sid})

        store_id = self.key_prefix + sid
        try:
            document = self.store.document(store_id).get()
            document = document.to_dict() if document.exists else None
        except Exception as e:
            log.error(f'Error while retrieving session from firestore (session id: {store_id}): {e}')
            # treat as session expired.
            document = None
        if document and document.pop('_expiration') <= datetime.utcnow().replace(tzinfo=utc):
            # Delete expired session
            self._delete_session_from_store(store_id)
            document = None
        if document is not None:
            try:
                # val = document['val']
                # data = self.serializer.loads(want_bytes(val))
                data = document
                permanent = self.cookie_name if data.pop('_permanent', None) else None
                return self.session_class(data, sid={self.cookie_name: sid}, permanent=permanent)
            except:
                return self.session_class(sid={self.cookie_name: sid})
        return self.session_class(sid={self.cookie_name: sid})

    def save_session(self, app, session, response):
        if self.cookie_domain is not None:
            domain = self.cookie_domain if self.cookie_domain else self.get_cookie_domain(app)
        else:
            domain = self.get_cookie_domain(app)
        path = self.cookie_path or self.get_cookie_path(app)

        if not session:
            if session.modified:
                self._delete_session_from_store(self.key_prefix + session.get_sid(self.cookie_name))
                response.delete_cookie(self.cookie_name, domain=domain, path=path)
            return

        httponly = self.cookie_httponly or self.get_cookie_httponly(app)
        secure = self.cookie_secure or self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)

        if session.modified:
            # The session was modified
            store_id = self.key_prefix + session.get_sid(self.cookie_name)
            # val = self.serializer.dumps(dict(session))
            val = {'_expiration': expires, '_permanent': session.is_permanent(self.cookie_name)}
            val.update(dict(session))
            try:
                # self.store.document(store_id).set({
                #     'val': val,
                #     '_expiration': expires
                # })
                self.store.document(store_id).set(val)
            except Exception as e:
                log.error(f'Error while updating session (session id: {store_id}): {e}')

        if self.use_signer:
            session_id = self._get_signer(app).sign(want_bytes(session.get_sid(self.cookie_name)))
        else:
            session_id = session.get_sid(self.cookie_name)
        response.set_cookie(self.cookie_name, session_id,
                            expires=expires, httponly=httponly,
                            domain=domain, path=path, secure=secure)
