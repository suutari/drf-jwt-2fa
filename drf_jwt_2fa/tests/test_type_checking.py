import typing
from collections.abc import Mapping, Sequence

import pytest

from .._type_checking import is_instance_of_type


class TypedItems:
    int_value: int
    int_none_union: int | None
    int_list: list[int]
    int_tuple: tuple[int, ...]
    int_seq: Sequence[int]
    int_str_pair: tuple[int, str]
    int_none_union_list: list[int | None]
    str_int_dict: dict[str, int]
    str_int_mapping: Mapping[str, int]


annots = typing.get_type_hints(TypedItems)


@pytest.mark.parametrize(
    "val, expected",
    [(42, True), ("a", False), (None, False)],
)
def test_int_value(val, expected):
    assert is_instance_of_type(val, int) is expected
    assert is_instance_of_type(val, annots["int_value"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [(42, True), (None, True), ("a", False)],
)
def test_int_none_union(val, expected):
    assert is_instance_of_type(val, int | None) is expected
    assert is_instance_of_type(val, annots["int_none_union"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [([1, 2], True), ([1, "a"], False)],
)
def test_int_list(val, expected):
    assert is_instance_of_type(val, list[int]) is expected
    assert is_instance_of_type(val, annots["int_list"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [((1, 2, 3), True), ([1, 2, 3], False), ((1, "a"), False)],
)
def test_int_tuple(val, expected):
    assert is_instance_of_type(val, tuple[int, ...]) is expected
    assert is_instance_of_type(val, annots["int_tuple"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [([1, 2, 3], True), ((1, 2, 3), True), ([1, 2, "a"], False)],
)
def test_int_seq(val, expected):
    assert is_instance_of_type(val, Sequence[int]) is expected
    assert is_instance_of_type(val, annots["int_seq"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [((1, "a"), True), ((1,), False), ((1, "a", "b"), False)],
)
def test_int_str_pair(val, expected):
    assert is_instance_of_type(val, tuple[int, str]) is expected
    assert is_instance_of_type(val, annots["int_str_pair"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [
        ([42, None], True),
        ([42], True),
        ([], True),
        ([None], True),
        (["abc"], False),
    ],
)
def test_int_none_union_list(val, expected):
    assert is_instance_of_type(val, list[int | None]) is expected
    assert is_instance_of_type(val, annots["int_none_union_list"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [({"a": 1}, True), (("a", 1), False), ({1: "a"}, False)],
)
def test_str_int_dict(val, expected):
    assert is_instance_of_type(val, dict[str, int]) is expected
    assert is_instance_of_type(val, annots["str_int_dict"]) is expected


@pytest.mark.parametrize(
    "val, expected",
    [({"a": 1}, True), (("a", 1), False), ({1: "a"}, False)],
)
def test_str_int_mapping(val, expected):
    assert is_instance_of_type(val, Mapping[str, int]) is expected
    assert is_instance_of_type(val, annots["str_int_mapping"]) is expected
