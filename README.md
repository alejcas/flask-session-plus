# Flask Multiple Sessions Interface 

#### Combine multiple sessions with different backends


Install it with:

`pip install flask-session-plus`

For Flask Multi Session to work, all you have to do is define all your sessions on a simple configuration variable called `SESSION_CONFIG`, and init the extension.


Session Configuration Example:

```python
SESSION_CONFIG = [
    {
        'cookie_name': 'csrf',
        'session_type': 'secure_cookie',
        'session_fields': ['csrf_token'],
    },
    {
        'cookie_name': 'session',
        'session_type': 'firestore',
        'session_fields': ['user_id', 'user_data'],
    },
    # ... as many sessions as you want 
]
```

> Caution: session_fields can collide if they have the same name and the same meaning. If they don't have the same meaning, you must use different field names.

The above configuration will define two session interfaces.
The first one is a secure cookie with 'csrf' name that will store the 'csrf_token' field.

The second one is a FirestoreSessionInterface that will set a cookie named 'session' with a single session id.
The 'user_id' and 'user_data' will be stored in the Google Cloud Firestore backend.

Finally register it as an extension:

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

- Secure Cookies Sessions
- Google Firestore Sessions

But working on:

- Redis Sessions
- SqlAlchemy Sessions
- MongoDB Sessions
- Memcache Sessions


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

- Properties available for the Google Firestore backend:

     Property name | Required | Default | Description
    --- | :---: | --- | ---
    `client` | `True` |  | The engine. An instance of firestore.Client.
    `collection` | `True` |  | The firestore collection you want to use to store sessions.
    `key_prefix` | `False` | `'session'` | The prefix to use in the document_id.
    `use_signer` | `False` | `False` | Whether to sign the session id cookie or not.
