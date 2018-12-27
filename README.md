# Flask Multiple Sessions Interface 

#### combine multiple sessions with different backends


Install it with:

`pip install flask-session-plus`

For Flask Multi Session to work, all you have to do is define all your sessions on a simple configuration variable called `SESSION_CONFIG`, and init the extension.


Session Configuration:

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

> Caution: session_fields can collide if they have the same meaning (aka: value). If not, you must use different field names.

The above configuration will define two session interfaces.
The first one is a secure cookie with 'csrf' name that will store the 'csrf_token' field.

The second one is a FirestoreSessionInterface that will store set a cookie named 'session' with a single session id.
The 'user_id' and 'user_data' will be stored in the Google Cloud Firestore backend.

Register as an extension:

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
