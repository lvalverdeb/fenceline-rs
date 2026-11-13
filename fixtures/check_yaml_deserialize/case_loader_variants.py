a = yaml.load(raw, yaml.SafeLoader)
b = yaml.load(raw, Loader=yaml.CSafeLoader)
c = yaml.load(raw, Loader=yaml.FullLoader)
