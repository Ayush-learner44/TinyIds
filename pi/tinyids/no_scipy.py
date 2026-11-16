"""Saves ~27 MB of RAM on the Pi.

lightgbm imports scipy at start-up, only to check "is the input a scipy sparse matrix?".
TinyIDS always gives it a plain numpy row, so scipy is never used. Here we give lightgbm a tiny empty
stand-in instead of the real scipy: every "is it sparse?" check simply answers "no".
Predictions and SHAP values are identical (checked on 200 test rows).

Must be imported BEFORE lightgbm (detector.py does that).
"""
import sys
import types


class NotSparse:
    """No real object is ever of this type, so lightgbm's isinstance checks are always False."""


if "scipy" not in sys.modules:                      # if real scipy is already loaded, change nothing
    scipy = types.ModuleType("scipy")
    scipy.sparse = types.ModuleType("scipy.sparse")
    for name in ("spmatrix", "sparray", "csr_matrix", "csc_matrix", "coo_matrix", "csr_array", "csc_array", "coo_array"):
        setattr(scipy.sparse, name, NotSparse)
    scipy.sparse.issparse = lambda x: False
    sys.modules["scipy"] = scipy
    sys.modules["scipy.sparse"] = scipy.sparse
