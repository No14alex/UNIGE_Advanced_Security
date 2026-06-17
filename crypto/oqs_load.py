
"""
Load the right oqs module
Ensure that the API uses the oqs of the liboqs-python package
"""

def _load_oqs_module():
    import oqs as imported_oqs

    if hasattr(imported_oqs, "KeyEncapsulation"):#hasattr(object, attribute)
        return imported_oqs

    import sysconfig
    from pathlib import Path
    from importlib import util as importlib_util

    purelib = Path(sysconfig.get_paths()["purelib"])
    candidate = purelib / "oqs" / "oqs.py"#constructs the path to the right oqs

    spec = importlib_util.spec_from_file_location("liboqs_python_compat", candidate)
    oqs_module = importlib_util.module_from_spec(spec)
    spec.loader.exec_module(oqs_module)

    return oqs_module


oqs = _load_oqs_module()