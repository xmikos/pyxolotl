import collections, json


class Config(collections.MutableMapping):
    """Configuration JSON storage class"""
    def __init__(self, filename='', default=None):
        self.filename = filename
        self.default = None
        self.config = {}
        self.changed = False

    def load(self):
        """Load config from file"""
        if not self.filename:
            raise RuntimeError('Config filename hasn\'t been specified!')

        try:
            self.config = json.load(open(self.filename))
        except (IOError, FileNotFoundError):
            self.config = {}
        self.changed = False

    def loads(self, json_str):
        """Load config from JSON string"""
        self.config = json.loads(json_str)
        self.changed = True

    def save(self):
        """Save config to file (only if config has changed)"""
        if not self.filename:
            raise RuntimeError('Config filename hasn\'t been specified!')

        if self.changed:
            with open(self.filename, 'w') as f:
                json.dump(self.config, f, indent=2, sort_keys=True)
                self.changed = False

    def __getitem__(self, key):
        try:
            return self.config[key]
        except KeyError:
            return self.default

    def __setitem__(self, key, value):
        self.config[key] = value
        self.changed = True

    def __delitem__(self, key):
        del self.config[key]
        self.changed = True

    def __iter__(self):
        return iter(self.config)

    def __len__(self):
        return len(self.config)


config = Config()
