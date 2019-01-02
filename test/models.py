import logging
from flask_login import UserMixin
from google.cloud import firestore

db = firestore.Client()

from google.cloud.exceptions import NotFound
from werkzeug.security import check_password_hash, generate_password_hash

log = logging.getLogger(__name__)


class User(UserMixin):

    def __init__(self, user_id, user_data):
        self.user_id = user_id
        self.user_ref = db.collection('users').document(user_id)
        self.email = user_data.pop('email', '')
        self.password = user_data.pop('password', '')
        self.active = user_data.pop('active', False)

        self.name = user_data.pop('name', '')

        # other attributes...
        self.country = user_data.pop('country', '')
        self.language = user_data.pop('language', '')
        self.timezone = user_data.pop('timezone', '')

        self.extra_data = user_data

    def __repr__(self):
        return f'name: {self.name} ({self.user_id})'

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'email': self.email,
            'password': self.password,
            'active': self.active,
            'name': self.name,
            'country': self.country,
            'language': self.language,
            'timezone': self.timezone,
        }

    def get_id(self):
        return self.user_id

    @property
    def is_active(self):
        return self.active

    @classmethod
    def get_user_by_id(cls, user_id):
        user_ref = db.collection('users').document(user_id)
        try:
            user = user_ref.get()
            user = cls(user_id=user_id, user_data=user.to_dict()) if user.exists else None
        except NotFound:
            user = None
        return user

    @classmethod
    def get_user_by_email(cls, email):
        user_ref = db.collection('users').where('email', '==', email).limit(1)
        try:
            user_ref.get()
            user = list(user_ref.get())  # a query returns an iterator
            user = user[0] if user else None
        except Exception as e:
            log.error(f'Error while getting username by email ({email}): {e}')
            user = None

        if user:
            return cls(user.id, user.to_dict())
        else:
            return None

    def set_password(self, password):
        new_password = generate_password_hash(password)
        try:
            self.user_ref.update({'password': new_password})
            self.password = new_password
        except Exception as e:
            log.error(f'Error while setting password on User ({self.user_id}): {e}')
            return False
        return True

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @classmethod
    def get_user_from_session(cls, session):
        # Avoids a database call
        if 'user_id' in session:
            return cls(session['user_id'], session.get('user_data', {}))
        else:
            return None
