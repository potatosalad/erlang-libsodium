"""Validated configuration for libsodium's generated NIF and Erlang sources."""

import re
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Discriminator, Field, Tag, field_validator, model_validator

CIdentifier = Annotated[str, Field(pattern=r"^[a-z_][a-zA-Z0-9_]*$")]
ErlangAtom = Annotated[str, Field(pattern=r"^[a-z][a-zA-Z0-9_]*$")]
ErlangVariable = Annotated[str, Field(pattern=r"^[A-Z][a-zA-Z0-9_]*$")]

UNSIGNED_C_TYPES = (
    "size_t",
    "unsigned long long",
    "unsigned long",
    "unsigned int",
    "uint64_t",
    "uint32_t",
    "uint16_t",
    "uint8_t",
    "unsigned char",
)
SIGNED_C_TYPES = ("int", "long", "long long", "int64_t", "int32_t")
LENGTH_C_TYPES = ("size_t", "unsigned long long")

RETURN_KINDS = ("binary", "uint", "int", "atom", "atom_cstr", "string")
RETURN_PATTERN = re.compile(r"^(?:(?P<kind>[a-z_]+):)?(?P<value>.+)$", re.DOTALL)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Constant(Model):
    """A zero-arity libsodium query such as `crypto_box_seedbytes()`."""

    name: CIdentifier
    type: Literal["size", "uint", "int", "atom", "string", "erlang"] = "size"
    c: str | None = Field(default=None, description="C expression; defaults to `<namespace>_<name>()`.")
    erlang: str | None = Field(default=None, description="For `type: erlang`, the Erlang expression returned (no NIF).")
    spec: str | None = Field(default=None, description="Erlang result type; required for `type: erlang`.")
    value: int | str | None = Field(default=None, description="Expected value checked by the generated tests.")
    doc: str | None = None

    @model_validator(mode="after")
    def valid_erlang(self) -> Self:
        if (self.type == "erlang") != (self.erlang is not None):
            raise ValueError(f"{self.name}: `erlang` is required by, and only allowed for, `type: erlang`")
        if self.type == "erlang" and (self.spec is None or self.doc is None):
            raise ValueError(f"{self.name}: `type: erlang` constants need a `spec` and a `doc`")
        return self


class BinaryArg(Model):
    """A variable-length binary passed as a pointer and a length."""

    type: Literal["binary"]
    name: CIdentifier
    len: CIdentifier | None = Field(default=None, description="C length variable; defaults to `<name>len`.")
    len_type: Literal["size_t", "unsigned long long"] = "unsigned long long"
    nullable: bool = Field(default=False, description="Pass NULL (and a zero length) for an empty binary.")
    min: str | None = Field(default=None, description="C expression for the minimum accepted length.")
    max: str | None = Field(default=None, description="C expression for the maximum accepted length.")
    work: bool = Field(default=True, description="Count the length towards the dirty scheduling threshold.")


class FixedArg(Model):
    """A binary that must be exactly `size` bytes long."""

    type: Literal["fixed"]
    name: CIdentifier
    size: str = Field(description="C expression for the required length, such as `crypto_box_SEEDBYTES`.")
    nullable: bool = Field(default=False, description="Pass NULL when the required length is zero.")


class CStringArg(Model):
    """A binary copied into a NUL-terminated C string."""

    type: Literal["cstring"]
    name: CIdentifier
    max: str | None = Field(default=None, description="C expression for the maximum length, excluding the NUL byte.")
    nullable: bool = Field(default=False, description="Pass NULL for an empty binary.")


class StateArg(Model):
    """A serialized state binary copied into a properly aligned, mutable C state."""

    type: Literal["state"]
    name: CIdentifier
    c_type: str
    size: str | None = Field(default=None, description="Expected binary length; defaults to `sizeof(c_type)`.")


class UIntArg(Model):
    type: Literal["uint"]
    name: CIdentifier
    c_type: Literal[UNSIGNED_C_TYPES] = "size_t"  # type: ignore[valid-type]
    min: str | None = None
    max: str | None = None
    work: bool = Field(default=False, description="Count the value towards the dirty scheduling threshold.")


class IntArg(Model):
    type: Literal["int"]
    name: CIdentifier
    c_type: Literal[SIGNED_C_TYPES] = "int"  # type: ignore[valid-type]
    min: str | None = None
    max: str | None = None


class EnumArg(Model):
    """An atom (or its integer value) mapped onto a C integer constant."""

    type: Literal["enum"]
    name: CIdentifier
    c_type: str = "int"
    values: dict[ErlangAtom, str] = Field(min_length=1, description="Atoms mapped to C constant expressions.")
    integers: bool = Field(default=True, description="Also accept the integer value of each constant.")


Arg = Annotated[BinaryArg | FixedArg | CStringArg | StateArg | UIntArg | IntArg | EnumArg, Field(discriminator="type")]


class BufferOutput(Model):
    """A binary allocated before the call and filled by libsodium."""

    type: Literal["buffer"] = "buffer"
    name: CIdentifier
    size: str = Field(description="C expression for the allocated length; argument lengths are in scope.")
    len: CIdentifier | None = Field(default=None, description="C variable receiving the produced length, if any.")
    len_type: Literal["size_t", "unsigned long long"] = "unsigned long long"
    length: str | None = Field(
        default=None, description="C expression for the returned length after the call; defaults to `len` or `size`."
    )
    copy_from: CIdentifier | None = Field(
        default=None, description="Copy this argument's bytes to the start of the buffer, which must be large enough."
    )


class StateOutput(Model):
    """An aligned C state initialized by the call and returned as a serialized binary."""

    type: Literal["state"]
    name: CIdentifier
    c_type: str


class ScalarOutput(Model):
    """A scalar local variable written by the call."""

    type: Literal["scalar"]
    name: CIdentifier
    c_type: str
    init: str = "0"


def _output_kind(value: object) -> str:
    if isinstance(value, dict):
        return value.get("type", "buffer")
    return getattr(value, "type", "buffer")


Output = Annotated[
    Annotated[BufferOutput, Tag("buffer")] | Annotated[StateOutput, Tag("state")] | Annotated[ScalarOutput, Tag("scalar")],
    Discriminator(_output_kind),
]

Return = str | list[str | list[str]]


class ErlangVariant(Model):
    """A public Erlang function clause mapped onto the native function."""

    params: list[ErlangVariable] = Field(default_factory=list)
    args: list[str] | None = Field(default=None, description="Erlang expressions for each native argument.")
    doc: str | None = None


class Function(Model):
    name: CIdentifier
    doc: str
    c: str | None = Field(default=None, description="The libsodium function; defaults to `<namespace>_<name>`.")
    args: list[Arg] = Field(default_factory=list)
    outputs: list[Output] = Field(default_factory=list)
    prelude: str | None = Field(default=None, description="C statements run after decoding and before allocation.")
    call: str | None = Field(default=None, description="C call expression; defaults to calling `c` with outputs and args.")
    rc_type: Literal["int", "void", "size_t", "uint32_t", "uint64_t", "const char *"] = "int"
    check: Literal["zero", "none"] = Field(
        default="zero", description="`zero` returns a non-zero `rc` to Erlang as an integer instead of the result."
    )
    returns: Return = Field(description="Output names, `kind:expression`, or a list for a tuple.")
    spec: str | None = Field(default=None, description="Erlang result type; derived from `returns` when omitted.")
    schedule: Literal["auto", "normal", "dirty_cpu", "dirty_io"] = "auto"
    update: bool = Field(
        default=False, description="Streaming update over (state, binary) that yields on timeslice exhaustion."
    )
    erlang: list[ErlangVariant] | None = None
    deprecated: str | None = None

    @model_validator(mode="after")
    def valid_function(self) -> Self:
        names = [a.name for a in self.args] + [o.name for o in self.outputs]
        if len(names) != len(set(names)):
            raise ValueError(f"{self.name}: argument and output names must be unique")
        if self.rc_type == "void" and self.check != "none":
            raise ValueError(f"{self.name}: void calls require `check: none`")
        if self.update:
            kinds = [a.type for a in self.args]
            if kinds != ["state", "binary"] or self.outputs:
                raise ValueError(f"{self.name}: update functions take (state, binary) and have no outputs")
        for variant in self.erlang or []:
            if variant.args is not None and len(variant.args) != len(self.args):
                raise ValueError(f"{self.name}: Erlang variant must supply {len(self.args)} native arguments")
        _validate_return(self.name, self.returns)
        return self


def _validate_return(name: str, value: Return) -> None:
    if isinstance(value, list):
        if len(value) < 2:
            raise ValueError(f"{name}: tuple results need at least two elements")
        for item in value:
            _validate_return(name, item)
        return
    match = RETURN_PATTERN.match(value)
    if match is None or (match.group("kind") is not None and match.group("kind") not in RETURN_KINDS):
        raise ValueError(f"{name}: invalid result {value!r}")


class TestCase(Model):
    """Erlang expressions run by the generated Common Test suite."""

    name: CIdentifier
    code: str = Field(description="Erlang expressions separated by commas; a crash or `badmatch` fails the test.")


class Namespace(Model):
    title: str
    doc: str
    module: ErlangAtom | None = Field(default=None, description="Public module; defaults to `libsodium_<namespace>`.")
    constants: list[Constant] = Field(default_factory=list)
    functions: list[Function] = Field(default_factory=list)
    example: str | None = Field(default=None, description="Erlang example shown in docs and run by tests.")
    tests: list[TestCase] = Field(default_factory=list)
    see_also: list[ErlangAtom] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_names(self) -> Self:
        seen: set[tuple[str, int]] = set()
        for constant in self.constants:
            key = (constant.name, 0)
            if key in seen:
                raise ValueError(f"Duplicate constant {constant.name}")
            seen.add(key)
        for function in self.functions:
            key = (function.name, len(function.args))
            if key in seen:
                raise ValueError(f"Duplicate function {function.name}/{len(function.args)}")
            seen.add(key)
        return self


class NIF(Model):
    atoms: list[CIdentifier] = Field(default_factory=list)
    dirty_threshold: int = Field(default=65536, gt=0, description="Work bytes above which `auto` runs dirty.")
    update_chunk: int = Field(default=65536, gt=0, description="Bytes absorbed between timeslice checks.")

    @field_validator("atoms")
    @classmethod
    def unique_atoms(cls, names: list[str]) -> list[str]:
        if len(names) != len(set(names)):
            raise ValueError("Atom names must be unique")
        return names


class Root(Model):
    nif: NIF = Field(default_factory=NIF)
    namespaces: dict[CIdentifier, Namespace] = Field(default_factory=dict)
