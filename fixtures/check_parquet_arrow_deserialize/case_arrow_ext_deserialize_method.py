class Ext:
    def __arrow_ext_deserialize__(self, storage, serialized):
        return cloudpickle.loads(serialized)
