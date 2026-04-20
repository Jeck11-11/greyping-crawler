"""Post-processing: fill 'not_found' into empty fields across API results.

Walks every Pydantic model in the response tree and replaces empty strings
with ``"not_found"`` and empty ``list[str]`` fields with ``["not_found"]``.
This makes the API output self-documenting for consumers (Xano, dashboards)
so they never see silent empty values for data that was looked up but absent.
"""

from __future__ import annotations

from typing import Union, get_args, get_origin

from pydantic import BaseModel

_NF = "not_found"

_SKIP_NAMES = frozenset({
    "error",
    "issues",
    "evidence",
    "found_on",
    "inferred_from",
})


def _is_str_list(annotation) -> bool:
    origin = get_origin(annotation)
    if origin is list:
        args = get_args(annotation)
        return bool(args) and args[0] is str
    return False


def _is_optional_str(annotation) -> bool:
    import types as _types
    origin = get_origin(annotation)
    args = get_args(annotation)
    if not args:
        return False
    if origin is Union or (hasattr(_types, "UnionType") and isinstance(annotation, _types.UnionType)):
        return str in args and type(None) in args
    return False


def _walk(obj: BaseModel) -> None:
    for name, field_info in type(obj).model_fields.items():
        if name in _SKIP_NAMES:
            continue

        val = getattr(obj, name)
        annotation = field_info.annotation

        if val is None:
            if _is_optional_str(annotation):
                setattr(obj, name, _NF)
            continue

        if isinstance(val, str) and val.strip() == "":
            setattr(obj, name, _NF)
        elif isinstance(val, list):
            if len(val) == 0 and _is_str_list(annotation):
                setattr(obj, name, [_NF])
            else:
                for item in val:
                    if isinstance(item, BaseModel):
                        _walk(item)
        elif isinstance(val, BaseModel):
            _walk(val)


def fill_not_found(obj: BaseModel) -> None:
    """Fill ``'not_found'`` into empty fields across a result tree."""
    _walk(obj)


__all__ = ["fill_not_found"]
