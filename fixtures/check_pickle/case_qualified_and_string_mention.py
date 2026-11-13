obj = cloudpickle.loads(blob)
obj2 = mypkg.pickle.loads(blob)
doc = "call pickle.loads(x) to restore"
cache = shelve.open(path)
