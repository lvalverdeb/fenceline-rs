pattern = re.compile(SAFE)  # (a+)+ in a comment
bad = re.search(r"(\w+\s?)*$", text)
