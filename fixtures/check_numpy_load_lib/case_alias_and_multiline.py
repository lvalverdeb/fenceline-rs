import numpy as np

lib = np.ctypeslib.load_library(
    "fastops.dll",
    ".",
)
arr = np.load("weights.npy")
