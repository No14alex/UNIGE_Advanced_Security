from importlib import util as importlib_util
from pathlib import Path
import sysconfig


def _load_oqs_module():
    """
    Charge le bon module OQS/liboqs-python.

    Dans cet environnement, un package tiers nomme `oqs` peut masquer
    `liboqs-python`. On tente donc l'import normal, puis on recharge
    explicitement `site-packages/oqs/oqs.py` si l'API attendue est absente.
    """
    import oqs as imported_oqs

    if hasattr(imported_oqs, "KeyEncapsulation") or hasattr(imported_oqs, "Signature"):
        return imported_oqs

    purelib = Path(sysconfig.get_paths()["purelib"])
    candidate = purelib / "oqs" / "oqs.py"
    if not candidate.exists():
        raise ImportError(
            "liboqs-python introuvable: le module 'oqs' importe n'expose ni "
            "KeyEncapsulation ni Signature, et aucun fallback n'a ete trouve."
        )

    spec = importlib_util.spec_from_file_location("liboqs_python_compat", candidate)
    if spec is None or spec.loader is None:
        raise ImportError(f"Impossible de charger le module OQS depuis {candidate}")

    oqs_module = importlib_util.module_from_spec(spec)
    spec.loader.exec_module(oqs_module)
    return oqs_module


oqs = _load_oqs_module()
