"""Privacy-preserving, bounded JSON comparisons; no values are persisted."""
import hashlib
import json
import re


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON key')
        result[key]=value
    return result


def _shape(value,depth=0):
    if depth>32:raise ValueError('JSON depth limit')
    if isinstance(value,dict):
        return {'object':[[key,_shape(value[key],depth+1)] for key in sorted(value)]}
    if isinstance(value,list):return {'array':[_shape(item,depth+1) for item in value]}
    if value is None:return 'null'
    if isinstance(value,bool):return 'boolean'
    if isinstance(value,(int,float)):return 'number'
    if isinstance(value,str):return 'string'
    raise ValueError('unsupported JSON')


def valid_owner_pointer(pointer):
    return (not pointer or (len(pointer)<=256 and pointer.startswith('/') and
            all(part and not re.search(r'~(?![01])',part) for part in pointer[1:].split('/'))))


def fingerprints(body, owner_pointer=''):
    try:
        if len(body)>32768:raise ValueError('JSON size limit')
        def reject_constant(value):raise ValueError('non-finite number')
        value=json.loads(body.decode('utf-8'),object_pairs_hook=_unique,parse_constant=reject_constant)
        canonical=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
        shape=json.dumps(_shape(value),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
        owner=None
        if owner_pointer:
            if not valid_owner_pointer(owner_pointer):raise ValueError('invalid JSON pointer')
            field=value
            for part in owner_pointer[1:].split('/'):
                part=part.replace('~1','/').replace('~0','~')
                if not isinstance(field,dict) or part not in field:
                    field=None
                    break
                field=field[part]
            if isinstance(field,str) and field:
                owner=hashlib.sha256(field.encode('utf-8')).digest()
        result=(hashlib.sha256(canonical).digest(),hashlib.sha256(shape).digest())
        return (*result,owner) if owner_pointer else result
    except (ValueError,TypeError,UnicodeError,RecursionError,OverflowError):
        return (None,None,None) if owner_pointer else (None,None)
