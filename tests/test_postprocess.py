"""Tests for the postprocess fill_not_found utility."""

from pydantic import BaseModel, Field

from src.postprocess import fill_not_found


class Inner(BaseModel):
    name: str = ""
    note: str | None = None


class Outer(BaseModel):
    title: str = ""
    inner: Inner = Field(default_factory=Inner)
    tags: list[str] = Field(default_factory=list)
    items: list[Inner] = Field(default_factory=list)
    error: str = ""


class TestFillNotFound:
    def test_empty_string_filled(self):
        obj = Outer()
        fill_not_found(obj)
        assert obj.title == "not_found"

    def test_whitespace_only_string_filled(self):
        obj = Outer(title="   ")
        fill_not_found(obj)
        assert obj.title == "not_found"

    def test_nonempty_string_preserved(self):
        obj = Outer(title="hello")
        fill_not_found(obj)
        assert obj.title == "hello"

    def test_optional_str_union_syntax_filled(self):
        obj = Inner(note=None)
        fill_not_found(obj)
        assert obj.note == "not_found"

    def test_nested_model_fields_filled(self):
        obj = Outer(inner=Inner(name=""))
        fill_not_found(obj)
        assert obj.inner.name == "not_found"

    def test_empty_list_of_strings_filled(self):
        obj = Outer(tags=[])
        fill_not_found(obj)
        assert obj.tags == ["not_found"]

    def test_nonempty_list_preserved(self):
        obj = Outer(tags=["a", "b"])
        fill_not_found(obj)
        assert obj.tags == ["a", "b"]

    def test_list_of_models_recursed(self):
        obj = Outer(items=[Inner(name="")])
        fill_not_found(obj)
        assert obj.items[0].name == "not_found"

    def test_skip_error_field(self):
        obj = Outer(error="")
        fill_not_found(obj)
        assert obj.error == ""

    def test_none_on_non_optional_ignored(self):
        obj = Outer(title="ok")
        fill_not_found(obj)
        assert obj.title == "ok"
