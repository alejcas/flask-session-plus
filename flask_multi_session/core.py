from flask.sessions import SessionMixin
from werkzeug._internal import _missing


class UpdateDictMixin(object):
    """ Makes dicts call `self.on_update` on modifications.
        self.on_update receives the dict instance and the attribute changed
    """

    on_update = None

    def calls_update(name):
        def oncall(self, *args, **kw):
            keys = list(super(UpdateDictMixin, self).keys()) if name == 'clear' else None
            rv = getattr(super(UpdateDictMixin, self), name)(*args, **kw)
            if self.on_update is not None:
                # TODO: delete the following comment
                # if name == '__setitem__':
                #     if args[0] in self and self.get(args[0]) == args[1]:
                #         pass
                #     else:
                #         self.on_update(self)
                # else:
                #     self.on_update(self)
                if name == 'clear':
                    for key in keys:
                        self.on_update(self, key)
                elif name == 'popitem':
                    self.on_update(self, rv[0])
                elif name == 'update':
                    for key in args[0]:
                        self.on_update(self, key)
                else:
                    self.on_update(self, args[0])
            return rv

        oncall.__name__ = name
        return oncall

    def setdefault(self, key, default=None):
        modified = key not in self
        rv = super(UpdateDictMixin, self).setdefault(key, default)
        if modified and self.on_update is not None:
            self.on_update(self, key)
        return rv

    def pop(self, key, default=_missing):
        modified = key in self
        if default is _missing:
            rv = super(UpdateDictMixin, self).pop(key)
        else:
            rv = super(UpdateDictMixin, self).pop(key, default)
        if modified and self.on_update is not None:
            self.on_update(self, key)
        return rv

    __setitem__ = calls_update('__setitem__')
    __delitem__ = calls_update('__delitem__')
    clear = calls_update('clear')
    popitem = calls_update('popitem')
    update = calls_update('update')
    del calls_update


class CallbackDict(UpdateDictMixin, dict):
    """A dict that calls a function passed every time something is changed.
    The function is passed the dict instance.
    """

    def __init__(self, initial=None, on_update=None):
        dict.__init__(self, initial or ())
        self.on_update = on_update

    def __repr__(self):
        return '<%s %s>' % (
            self.__class__.__name__,
            dict.__repr__(self)
        )


class ServerSideSession(CallbackDict, SessionMixin):
    """ Baseclass for server-side based sessions.
        Tracks the keys that were modified
    """

    def __init__(self, initial=None, sid=None, permanent=None):
        def on_update(self, updated_key):
            self.modified = True
            self.tracked_status.add(updated_key)

        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        if permanent:
            self.permanent = permanent
        self.modified = False
        self.tracked_status = set()



