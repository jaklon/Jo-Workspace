"""Original evidence archival using the current Windows user's DPAPI keys."""
import sys


def available():
    if sys.platform != 'win32':
        return False
    try:
        import win32crypt
        return bool(win32crypt.CryptProtectData)
    except ImportError:
        return False


def entropy(evidence_id, original_hash):
    return ('AgentOS-Evidence-v1:' + evidence_id + ':' + original_hash).encode('ascii')


def protect(raw, evidence_id, original_hash):
    import win32crypt
    # UI_FORBIDDEN; deliberately no LOCAL_MACHINE flag.
    return win32crypt.CryptProtectData(raw.encode('utf-8'), 'Jo Workspace evidence', entropy(evidence_id, original_hash), None, None, 1)


def unprotect(cipher, evidence_id, original_hash):
    import win32crypt
    _, raw = win32crypt.CryptUnprotectData(cipher, entropy(evidence_id, original_hash), None, None, 1)
    return raw.decode('utf-8')
