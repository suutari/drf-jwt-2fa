import types
from collections.abc import Mapping, Sequence
from typing import get_args, get_origin


def is_instance_of_type(value: object, tp: type) -> bool:
    return _isinstance(value, tp)


def _isinstance(value: object, tp: type) -> bool:
    """
    Check if value is an instance of type tp, handling type annotations.
    """
    origin = get_origin(tp)

    if origin is types.UnionType:  # Union type (e.g. int | None)
        return isinstance(value, tp)

    # Sequence types (e.g. Sequence, list, tuple)
    if isinstance(origin, type) and issubclass(origin, Sequence):
        if not isinstance(value, origin):
            return False
        tp_args = get_args(tp)
        if origin is tuple and tp_args != (tp_args[0], ...):
            # Fixed-length tuple with specific types for each position
            return len(value) == len(get_args(tp)) and all(
                _isinstance(x, t)
                for (x, t) in zip(value, tp_args, strict=True)
            )
        return all(_isinstance(item, tp_args[0]) for item in value)

    if isinstance(origin, type) and issubclass(origin, Mapping):
        if not isinstance(value, origin):
            return False
        (kt, vt) = get_args(tp)
        return all(
            _isinstance(k, kt) and _isinstance(v, vt)
            for (k, v) in value.items()
        )

    return isinstance(value, tp)
