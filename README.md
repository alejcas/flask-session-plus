# Flask Multiple Sessions Interface 

#### Combine multiple sessions with different backends

With Flask Session Plus you can use multiple different backends and choose what session variables are saved on what backend.


##### Python version:
> It works on python >= 3.4
> For the moment it should work on python 2.7 but it is not tested yet. If something does not work properly please open a bug report.
>

##### Install it with:

`pip install flask-session-plus`

For Flask Multi Session to work, all you have to do is define all your sessions on a simple configuration variable called `SESSION_CONFIG`, and init the extension.


##### Session Configuration Example:

```python
# example using the Google Firestore backend
from google.cloud import firestore

SESSION_CONFIG = [
    # First session will store the csrf_token only on it's own cookie.
    {
        'cookie_name': 'csrf',
        'session_type': 'secure_cookie',
        'session_fields': ['csrf_token'],
    },
    # Second session will store the user logged in inside the firestore sessions collection.
    {
        'cookie_name': 'session',
        'session_type': 'firestore',
        'session_fields': ['user_id', 'user_data'],
        'client': firestore.Client(),
        'collection': 'sessions',
    },
    # Third session will store any other values set on the Flask session on it's own secure cookie
    {
        'cookie_name': 'data',
        'session_type': 'secure_cookie',
        'session_fields': 'auto'
    },
    # ... as many sessions as you want 
]
```

> Caution: session_fields can collide if they have the same name and the same meaning. If they don't have the same meaning, you must use different field names.

The above configuration will define three session interfaces:

- The first one is a secure cookie with 'csrf' name that will store the 'csrf_token' field.
- The second one is a FirestoreSessionInterface that will set a cookie named 'session' with a single session id. The 'user_id' and 'user_data' will be stored in the Google Cloud Firestore backend.
- The third one will store any other varibles stored in the session on another secure cookie.

After configuring just register it as an extension:

```python
from flask_session_plus import Session

app = Flask(__name__)

Session(app)
```

or

```python
from flask_session_plus import Session

app = Flask(__name__)

session = Session()

session.init_app(app)
```


---

### Current available backends:

- Secure Cookies Sessions (session_type key: `'secure_cookie'`)
- Google Firestore Sessions (session_type key: `'firestore'`)
- Redis Sessions (session_type key: `'redis'`)
- MongoDB Sessions (session_type key: `'mongodb'`)
- Memcache Sessions (session_type key: `'memcache'`)


More Backend Session Interfaces can be created by subclassing `BackendSessionInterface` and overwriting the following methods:

  1. `__init__`
  1. `open_session`
  1. `save_session`

### All posible values for Session configuration:


- Common properties for all backends:

    Property name | Required | Default | Description
    --- | :---: | --- | ---
    `cookie_name` | `True` | | The name of the cookie to use. It also serves as a key for different sessions.
    `session_type` | `False` | `'secure_cookie'` | The session backend to use.
    `session_fields` | `False` | `[]` | The fields that are owned by this session. An empty list means: 'include all fields'. It can be: 1) an array of fields to include, 2) a dict with the keys 'include' or 'exclude', to include or exclude a list of fields or 3) the string 'auto' to auto exclude all the other session fields.

- Properties for SecureCookie (available for all backends):
    
    Property name | Required | Default | Description
    --- | :---: | --- | ---
    `cookie_domain` | `False` |  | The domain for the session cookie. If this is not set, the cookie will be valid for all subdomains of SERVER_NAME..
    `cookie_path` | `False` |  | The path for the session cookie. If this is not set the cookie will be valid for all of APPLICATION_ROOT or if that is not set for '/'.
    `cookie_httponly` | `False` | `True` | Whether to allow access the cookie only over http or other ways (javascript).
    `cookie_secure` | `False` | `False` | Whether to serve this cookie over https only.
    `cookie_max_age` | `False` | `None` | The cookie expiration time in seconds. None means the cookie will expire at browser close.
    `cookie_samesite` | `False` | `'Lax'` | The cookie samesite configuration.
    
- Properties available for any other backend rather than SecureCookie:

    Property name | Required | Default | Description
    --- | :---: | --- | ---
    `session_lifetime` | `False` | `timedelta(days=1)` | The duration for a valid session. Not used on SecureCookie backend.  
    `key_prefix` | `False` | `'session'` | The prefix to use in the store_id.
    `use_signer` | `False` | `False` | Whether to sign the session id cookie or not.
    
- Properties available for the Google Firestore backend:

     Property name | Required | Default | Description
    --- | :---: | --- | ---
    `client` | `True` |  | The engine. An instance of firestore.Client.
    `collection` | `True` |  | The firestore collection you want to use to store sessions.
    
- Properties available for the Redis backend:

     Property name | Required | Default | Description
    --- | :---: | --- | ---
    `client` | `True` |  | The engine. An instance of redis.Redis.

- Properties available for the MongoDB backend:

     Property name | Required | Default | Description
    --- | :---: | --- | ---
    `client` | `True` |  | The engine. An instance of redis.Redis.
    `db` | `True` |  | The database you want to use.
    `collection` | `True` |  | The mongodb collection you want to use to store sessions.

- Properties available for the Memcache backend:

     Property name | Required | Default | Description
    --- | :---: | --- | ---
    `client` | `True` |  | The engine. An instance of memcache.Client.
