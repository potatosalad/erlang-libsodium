"""Native and Erlang code fragments derived from namespace definitions."""

from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING

from .. import schema

if TYPE_CHECKING:
    from . import Context

UNSIGNED_LIMITS = {
    "size_t": "SIZE_MAX",
    "unsigned long long": "ULLONG_MAX",
    "unsigned long": "ULONG_MAX",
    "unsigned int": "UINT_MAX",
    "uint64_t": "UINT64_MAX",
    "uint32_t": "UINT32_MAX",
    "uint16_t": "UINT16_MAX",
    "uint8_t": "UINT8_MAX",
    "unsigned char": "UCHAR_MAX",
}
SIGNED_LIMITS = {
    "int": ("INT_MIN", "INT_MAX"),
    "long": ("LONG_MIN", "LONG_MAX"),
    "long long": ("LLONG_MIN", "LLONG_MAX"),
    "int64_t": ("INT64_MIN", "INT64_MAX"),
    "int32_t": ("INT32_MIN", "INT32_MAX"),
}
DIRTY_FLAGS = {
    "normal": "ERL_NIF_NORMAL_JOB_BOUND",
    "auto": "ERL_NIF_NORMAL_JOB_BOUND",
    "dirty_cpu": "ERL_NIF_DIRTY_JOB_CPU_BOUND",
    "dirty_io": "ERL_NIF_DIRTY_JOB_IO_BOUND",
}
CONSTANT_TERMS = {
    "size": "enif_make_uint64(env, (ErlNifUInt64)({}))",
    "uint": "enif_make_uint64(env, (ErlNifUInt64)({}))",
    "int": "enif_make_int64(env, (ErlNifSInt64)({}))",
    "atom": "enif_make_atom(env, {})",
    "string": "libsodium_nif_make_string(env, {})",
}
CONSTANT_SPECS = {
    "size": "non_neg_integer()",
    "uint": "non_neg_integer()",
    "int": "integer()",
    "atom": "atom()",
    "string": "binary()",
}
CONSTANT_DOCS = {
    "size": "Return `{c}`, in bytes.",
    "uint": "Return `{c}`.",
    "int": "Return `{c}`.",
    "atom": "Return `{c}` as an atom.",
    "string": "Return `{c}` as a binary.",
}


# Categories follow the structure of the libsodium documentation.
GROUPS = (
    ("Secret-key cryptography", ("crypto_aead_", "crypto_auth", "crypto_ipcrypt", "crypto_secretbox", "crypto_secretstream_")),
    ("Public-key cryptography", ("crypto_box", "crypto_kem", "crypto_kx", "crypto_sign")),
    ("Hashing", ("crypto_generichash", "crypto_hash", "crypto_shorthash", "crypto_xof_")),
    ("Password hashing", ("crypto_pwhash",)),
    ("Key derivation", ("crypto_kdf",)),
    ("Advanced", ("crypto_core_", "crypto_onetimeauth", "crypto_scalarmult", "crypto_stream", "crypto_verify_")),
    ("Helpers", ("randombytes", "runtime", "utils", "version")),
)


def namespace_group(name: str) -> str:
    for group, prefixes in GROUPS:
        if any(name == prefix or name.startswith(prefix) for prefix in prefixes):
            return group
    raise ValueError(f"No documentation group for namespace {name}")


ERLANG_RESERVED = frozenset(
    "after and andalso band begin bnot bor bsl bsr bxor case catch cond div else end fun if let maybe not of or "
    "orelse receive rem try when xor".split()
)


def erlang_atom(name: str) -> str:
    return f"'{name}'" if name in ERLANG_RESERVED else name


def state_type_var(c_type: str) -> str:
    return f"libsodium_nif_state_type_{c_type}"


def erlang_variable(name: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in name.split("_") if part)


def indent(lines: list[str], depth: int = 1) -> str:
    prefix = "    " * depth
    return "\n".join((prefix + line) if line else "" for line in lines)


@dataclass
class ConstantCtx:
    namespace: "NamespaceCtx" = field(repr=False)
    schema: schema.Constant

    @property
    def name(self) -> str:
        return self.schema.name

    @property
    def nif_name(self) -> str:
        return f"{self.namespace.name}_{self.name}"

    @property
    def arity(self) -> int:
        return 0

    @property
    def c_name(self) -> str:
        return f"libsodium_nif_{self.nif_name}_0"

    @property
    def params(self) -> list[str]:
        return []

    @property
    def stub_params(self) -> list[str]:
        return []

    @property
    def c_expr(self) -> str:
        return self.schema.c or f"{self.namespace.c_prefix}_{self.name}()"

    @property
    def c_term(self) -> str:
        return CONSTANT_TERMS[self.schema.type].format(self.c_expr)

    @property
    def dirty_flag(self) -> str:
        return DIRTY_FLAGS["normal"]

    @property
    def result_type(self) -> str:
        return self.schema.spec or CONSTANT_SPECS[self.schema.type]

    @property
    def is_native(self) -> bool:
        return self.schema.type != "erlang"

    @property
    def doc(self) -> str:
        if self.schema.doc:
            return self.schema.doc.strip()
        return CONSTANT_DOCS[self.schema.type].format(c=self.c_expr)

    @property
    def nif_spec(self) -> str:
        return f"{self.nif_name}() -> Result when Result :: {self.result_type}"

    @property
    def public(self) -> "PublicFunction":
        return PublicFunction(
            name=self.name,
            params=[],
            args=[],
            types={},
            result_type=self.result_type,
            doc=self.doc,
            target=self,
            expression=self.schema.erlang,
        )


@dataclass
class FunctionCtx:
    namespace: "NamespaceCtx" = field(repr=False)
    schema: schema.Function

    @property
    def name(self) -> str:
        return self.schema.name

    @property
    def nif_name(self) -> str:
        return f"{self.namespace.name}_{self.name}"

    @property
    def arity(self) -> int:
        return len(self.schema.args)

    @property
    def c_name(self) -> str:
        return f"libsodium_nif_{self.nif_name}_{self.arity}"

    @property
    def c_function(self) -> str:
        return self.schema.c or f"{self.namespace.c_prefix}_{self.name}"

    @property
    def args(self) -> list[schema.Arg]:
        return self.schema.args

    @property
    def outputs(self) -> list[schema.Output]:
        return self.schema.outputs

    @property
    def schedule(self) -> str:
        if self.schema.schedule == "auto" and not self.work_terms:
            return "normal"
        if self.schema.update:
            return "normal"
        return self.schema.schedule

    @property
    def dirty_flag(self) -> str:
        return DIRTY_FLAGS[self.schedule]

    @property
    def is_update(self) -> bool:
        return self.schema.update

    @property
    def update_state(self) -> schema.StateArg:
        state = self.args[0]
        assert isinstance(state, schema.StateArg)
        return state

    @property
    def update_state_type(self) -> str:
        return state_type_var(self.update_state.c_type)

    @property
    def update_call(self) -> str:
        if self.schema.call:
            return self.schema.call
        state, data = self.args
        assert isinstance(data, schema.BinaryArg)
        return f"{self.c_function}(({state.c_type} *)state, {data.name}, {data.name}len)"

    # Native fragments.

    def _len(self, arg: schema.BinaryArg | schema.BufferOutput) -> str:
        return arg.len or f"{arg.name}len"

    @cached_property
    def work_terms(self) -> list[str]:
        terms = []
        for arg in self.args:
            if isinstance(arg, schema.BinaryArg) and arg.work:
                terms.append(f"(ErlNifUInt64)({self._len(arg)})")
            elif isinstance(arg, schema.UIntArg) and arg.work:
                terms.append(f"(ErlNifUInt64)({arg.name})")
        return terms

    @property
    def work_expr(self) -> str:
        return " + ".join(self.work_terms)

    @cached_property
    def declarations(self) -> list[str]:
        lines = ["ERL_NIF_TERM result = THE_NON_VALUE;"]
        for arg in self.args:
            match arg:
                case schema.BinaryArg():
                    lines += [
                        f"ErlNifBinary {arg.name}_bin;",
                        f"const unsigned char *{arg.name} = NULL;",
                        f"{arg.len_type} {self._len(arg)} = 0;",
                    ]
                case schema.FixedArg():
                    lines += [f"ErlNifBinary {arg.name}_bin;", f"const unsigned char *{arg.name} = NULL;"]
                case schema.CStringArg():
                    lines += [f"ErlNifBinary {arg.name}_bin;", f"char *{arg.name}_str = NULL;", f"const char *{arg.name} = NULL;"]
                case schema.StateArg():
                    lines += [f"libsodium_nif_state_t *{arg.name}_res = NULL;", f"{arg.c_type} {arg.name};"]
                case schema.UIntArg():
                    lines += [f"ErlNifUInt64 {arg.name}_u64;", f"{arg.c_type} {arg.name} = 0;"]
                case schema.IntArg():
                    lines += [f"ErlNifSInt64 {arg.name}_s64;", f"{arg.c_type} {arg.name} = 0;"]
                case schema.EnumArg():
                    lines += [f"{arg.c_type} {arg.name} = ({arg.c_type})0;"]
        for output in self.outputs:
            match output:
                case schema.BufferOutput():
                    lines += [
                        f"ErlNifBinary {output.name}_bin;",
                        f"int {output.name}_alloc = 0;",
                        f"size_t {output.name}_size = 0;",
                        f"unsigned char *{output.name} = NULL;",
                    ]
                    if output.len:
                        lines.append(f"{output.len_type} {output.len} = 0;")
                case schema.StateOutput():
                    lines.append(f"{output.c_type} {output.name};")
                case schema.ScalarOutput():
                    lines.append(f"{output.c_type} {output.name} = {output.init};")
        if self.schema.rc_type == "const char *":
            lines.append("const char *rc = NULL;")
        elif self.schema.rc_type != "void":
            lines.append(f"{self.schema.rc_type} rc = 0;")
        return lines

    def _badarg_if(self, condition: str) -> list[str]:
        return [f"if ({condition}) {{", "    result = enif_make_badarg(env);", "    goto cleanup;", "}"]

    @cached_property
    def decode(self) -> list[str]:
        lines: list[str] = []
        for index, arg in enumerate(self.args):
            term = f"argv[{index}]"
            match arg:
                case schema.BinaryArg():
                    lines += self._badarg_if(f"!enif_inspect_binary(env, {term}, &{arg.name}_bin)")
                    lines.append(f"{self._len(arg)} = ({arg.len_type})({arg.name}_bin.size);")
                    if arg.nullable:
                        lines.append(f"{arg.name} = ({arg.name}_bin.size == 0) ? NULL : {arg.name}_bin.data;")
                    else:
                        lines.append(f"{arg.name} = {arg.name}_bin.data;")
                    if arg.min:
                        lines += self._badarg_if(f"{self._len(arg)} < ({arg.min})")
                    if arg.max:
                        lines += self._badarg_if(f"{self._len(arg)} > ({arg.max})")
                case schema.FixedArg():
                    lines += self._badarg_if(
                        f"!enif_inspect_binary(env, {term}, &{arg.name}_bin) || {arg.name}_bin.size != (size_t)({arg.size})"
                    )
                    if arg.nullable:
                        lines.append(f"{arg.name} = ({arg.name}_bin.size == 0) ? NULL : {arg.name}_bin.data;")
                    else:
                        lines.append(f"{arg.name} = {arg.name}_bin.data;")
                case schema.CStringArg():
                    lines += self._badarg_if(f"!enif_inspect_binary(env, {term}, &{arg.name}_bin)")
                    if arg.max:
                        lines += self._badarg_if(f"{arg.name}_bin.size > (size_t)({arg.max})")
                    lines += self._badarg_if(f"memchr({arg.name}_bin.data, 0, {arg.name}_bin.size) != NULL")
                case schema.StateArg():
                    lines += self._badarg_if(
                        f"!libsodium_nif_state_get(env, {term}, &{state_type_var(arg.c_type)}, &{arg.name}_res)"
                    )
                    lines.append(f"(void)memcpy((void *)&{arg.name}, {arg.name}_res->state, sizeof({arg.name}));")
                case schema.UIntArg():
                    lines += self._badarg_if(
                        f"!enif_get_uint64(env, {term}, &{arg.name}_u64) || {arg.name}_u64 > (ErlNifUInt64)({UNSIGNED_LIMITS[arg.c_type]})"
                    )
                    lines.append(f"{arg.name} = ({arg.c_type})({arg.name}_u64);")
                    if arg.min:
                        lines += self._badarg_if(f"{arg.name} < ({arg.min})")
                    if arg.max:
                        lines += self._badarg_if(f"{arg.name} > ({arg.max})")
                case schema.IntArg():
                    low, high = SIGNED_LIMITS[arg.c_type]
                    lines += self._badarg_if(
                        f"!enif_get_int64(env, {term}, &{arg.name}_s64) || {arg.name}_s64 < (ErlNifSInt64)({low}) || {arg.name}_s64 > (ErlNifSInt64)({high})"
                    )
                    lines.append(f"{arg.name} = ({arg.c_type})({arg.name}_s64);")
                    if arg.min:
                        lines += self._badarg_if(f"{arg.name} < ({arg.min})")
                    if arg.max:
                        lines += self._badarg_if(f"{arg.name} > ({arg.max})")
                case schema.EnumArg():
                    lines += self._decode_enum(term, arg)
        return lines

    def _decode_enum(self, term: str, arg: schema.EnumArg) -> list[str]:
        lines = [f"if (enif_is_atom(env, {term})) {{"]
        for position, (atom, value) in enumerate(arg.values.items()):
            self.namespace.ctx.nif.make_atom(atom)
            keyword = "if" if position == 0 else "} else if"
            lines += [
                f"    {keyword} (enif_is_identical({term}, ATOM({atom}))) {{",
                f"        {arg.name} = ({arg.c_type})({value});",
            ]
        lines += ["    } else {", "        result = enif_make_badarg(env);", "        goto cleanup;", "    }"]
        if not arg.integers:
            lines += ["} else {", "    result = enif_make_badarg(env);", "    goto cleanup;", "}"]
            return lines
        lines += [
            "} else {",
            f"    ErlNifSInt64 {arg.name}_s64;",
            f"    if (!enif_get_int64(env, {term}, &{arg.name}_s64)) {{",
            "        result = enif_make_badarg(env);",
            "        goto cleanup;",
            "    }",
        ]
        matches = " && ".join(f"{arg.name}_s64 != (ErlNifSInt64)({value})" for value in arg.values.values())
        lines += [
            f"    if ({matches}) {{",
            "        result = enif_make_badarg(env);",
            "        goto cleanup;",
            "    }",
            f"    {arg.name} = ({arg.c_type})({arg.name}_s64);",
            "}",
        ]
        return lines

    @cached_property
    def prepare(self) -> list[str]:
        """Allocations that follow scheduling decisions."""
        lines: list[str] = []
        for arg in self.args:
            if isinstance(arg, schema.CStringArg):
                block = [
                    f"{arg.name}_str = (char *)enif_alloc({arg.name}_bin.size + 1);",
                    f"if ({arg.name}_str == NULL) {{",
                    '    result = EXCP_ERROR(env, "Can\'t allocate memory");',
                    "    goto cleanup;",
                    "}",
                    f"(void)memcpy({arg.name}_str, {arg.name}_bin.data, {arg.name}_bin.size);",
                    f"{arg.name}_str[{arg.name}_bin.size] = '\\0';",
                    f"{arg.name} = (const char *){arg.name}_str;",
                ]
                if arg.nullable:
                    block = [f"if ({arg.name}_bin.size > 0) {{", *("    " + line for line in block), "}"]
                lines += block
        if self.schema.prelude:
            lines += self.schema.prelude.strip().splitlines()
        for output in self.outputs:
            if isinstance(output, schema.BufferOutput):
                lines += [
                    f"{output.name}_size = (size_t)({output.size});",
                    f"if (!enif_alloc_binary({output.name}_size, &{output.name}_bin)) {{",
                    '    result = EXCP_ERROR(env, "Can\'t allocate memory");',
                    "    goto cleanup;",
                    "}",
                    f"{output.name}_alloc = 1;",
                    f"{output.name} = {output.name}_bin.data;",
                ]
                if output.copy_from:
                    source = output.copy_from
                    lines += self._badarg_if(f"{source}_bin.size > {output.name}_size")
                    lines += [
                        f"(void)memcpy({output.name}, {source}_bin.data, {source}_bin.size);",
                        f"(void){source};",
                    ]
                if output.len:
                    lines.append(f"{output.len} = ({output.len_type})({output.name}_size);")
        return lines

    @property
    def call_expr(self) -> str:
        if self.schema.call:
            return " ".join(self.schema.call.split())
        parts: list[str] = []
        for output in self.outputs:
            match output:
                case schema.BufferOutput():
                    parts.append(output.name)
                    if output.len:
                        parts.append(f"&{output.len}")
                case schema.StateOutput() | schema.ScalarOutput():
                    parts.append(f"&{output.name}")
        for arg in self.args:
            match arg:
                case schema.BinaryArg():
                    parts += [arg.name, self._len(arg)]
                case schema.StateArg():
                    parts.append(f"&{arg.name}")
                case _:
                    parts.append(arg.name)
        return f"{self.c_function}({', '.join(parts)})"

    @property
    def call_stmt(self) -> list[str]:
        if self.schema.rc_type == "void":
            lines = [f"{self.call_expr};"]
        else:
            lines = [f"rc = {self.call_expr};"]
        if self.schema.deprecated:
            # libsodium marks some functions deprecated; keep exposing them without warnings.
            lines = [
                '_Pragma("GCC diagnostic push")',
                '_Pragma("GCC diagnostic ignored \\"-Wdeprecated-declarations\\"")',
                *lines,
                '_Pragma("GCC diagnostic pop")',
            ]
        if self.schema.check == "zero":
            lines += ["if (rc != 0) {", "    result = enif_make_int(env, (int)rc);", "    goto cleanup;", "}"]
        return lines

    def _named(self, name: str):
        for item in [*self.args, *self.outputs]:
            if item.name == name:
                return item
        raise ValueError(f"{self.nif_name}: unknown result {name!r}")

    def _result(self, value: schema.Return, lines: list[str], counter: list[int]) -> str:
        if isinstance(value, list):
            items = [self._result(item, lines, counter) for item in value]
            return f"enif_make_tuple{len(items)}(env, {', '.join(items)})" if len(items) <= 9 else self._tuple(items)
        match = schema.RETURN_PATTERN.match(value)
        assert match is not None
        kind, expr = match.group("kind") or "binary", match.group("value")
        if kind == "binary":
            item = self._named(expr)
            term = f"term{counter[0]}"
            counter[0] += 1
            match item:
                case schema.BufferOutput():
                    length = item.length or item.len
                    if length:
                        lines += [
                            f"if ((size_t)({length}) < {item.name}_size) {{",
                            f"    sodium_memzero({item.name} + (size_t)({length}), {item.name}_size - (size_t)({length}));",
                            f"    if (!enif_realloc_binary(&{item.name}_bin, (size_t)({length}))) {{",
                            '        result = EXCP_ERROR(env, "Can\'t allocate memory");',
                            "        goto cleanup;",
                            "    }",
                            "}",
                        ]
                    lines += [
                        f"ERL_NIF_TERM {term} = enif_make_binary(env, &{item.name}_bin);",
                        f"{item.name}_alloc = 0;",
                    ]
                case schema.StateArg() | schema.StateOutput():
                    lines += [
                        f"ERL_NIF_TERM {term} = libsodium_nif_state_make(env, &{state_type_var(item.c_type)}, (const void *)&{item.name});",
                        f"if (enif_is_exception(env, {term})) {{",
                        f"    result = {term};",
                        "    goto cleanup;",
                        "}",
                    ]
                case schema.FixedArg() | schema.BinaryArg():
                    lines.append(f"ERL_NIF_TERM {term} = argv[{self.args.index(item)}];")
                case _:
                    raise ValueError(f"{self.nif_name}: {expr!r} is not a binary")
            return term
        if kind == "uint":
            return f"enif_make_uint64(env, (ErlNifUInt64)({expr}))"
        if kind == "int":
            return f"enif_make_int64(env, (ErlNifSInt64)({expr}))"
        if kind == "atom":
            self.namespace.ctx.nif.make_atom(expr)
            return f"ATOM({expr})"
        if kind == "atom_cstr":
            return f"enif_make_atom(env, {expr})"
        if kind == "string":
            return f"libsodium_nif_make_string(env, {expr})"
        raise ValueError(f"{self.nif_name}: invalid result kind {kind!r}")

    def _tuple(self, items: list[str]) -> str:
        return f"enif_make_tuple_from_array(env, (ERL_NIF_TERM[]){{{', '.join(items)}}}, {len(items)})"

    @cached_property
    def build_result(self) -> list[str]:
        lines: list[str] = []
        term = self._result(self.schema.returns, lines, [0])
        lines.append(f"result = {term};")
        return lines

    @cached_property
    def cleanup(self) -> list[str]:
        lines: list[str] = []
        for output in self.outputs:
            match output:
                case schema.BufferOutput():
                    lines += [
                        f"if ({output.name}_alloc) {{",
                        f"    sodium_memzero({output.name}_bin.data, {output.name}_bin.size);",
                        f"    enif_release_binary(&{output.name}_bin);",
                        "}",
                    ]
                case schema.StateOutput():
                    lines.append(f"sodium_memzero((void *)&{output.name}, sizeof({output.name}));")
        for arg in self.args:
            match arg:
                case schema.CStringArg():
                    lines += [
                        f"if ({arg.name}_str != NULL) {{",
                        f"    sodium_memzero({arg.name}_str, {arg.name}_bin.size + 1);",
                        f"    enif_free({arg.name}_str);",
                        "}",
                    ]
                case schema.StateArg():
                    lines.append(f"sodium_memzero((void *)&{arg.name}, sizeof({arg.name}));")
        return lines

    @property
    def unused(self) -> list[str]:
        return []

    # Erlang fragments.

    def arg_type(self, arg: schema.Arg, local: bool = False) -> str:
        match arg:
            case schema.StateArg():
                return "state()" if local else f"{arg.c_type}()"
            case schema.UIntArg():
                return "non_neg_integer()"
            case schema.IntArg():
                return "integer()"
            case schema.EnumArg():
                return " | ".join([*arg.values, *(["integer()"] if arg.integers else [])])
            case _:
                return "binary()"

    def _result_type(self, value: schema.Return, local: bool) -> str:
        if isinstance(value, list):
            return "{" + ", ".join(self._result_type(item, local) for item in value) + "}"
        match = schema.RETURN_PATTERN.match(value)
        assert match is not None
        kind, expr = match.group("kind") or "binary", match.group("value")
        if kind == "binary":
            item = self._named(expr)
            if isinstance(item, (schema.StateArg, schema.StateOutput)):
                return "state()" if local else f"{item.c_type}()"
        return {
            "binary": "binary()",
            "uint": "non_neg_integer()",
            "int": "integer()",
            "atom": expr,
            "atom_cstr": "atom()",
            "string": "binary()",
        }[kind]

    def result_type(self, local: bool = False) -> str:
        if self.schema.spec:
            state = self.namespace.state_c_type
            return self.schema.spec if local or state is None else self.schema.spec.replace("state()", f"{state}()")
        result = self._result_type(self.schema.returns, local)
        if self.schema.check == "zero":
            result += " | -1"
        return result

    @property
    def params(self) -> list[str]:
        return [erlang_variable(arg.name) for arg in self.args]

    @property
    def stub_params(self) -> list[str]:
        return [f"_{param}" for param in self.params]

    @property
    def nif_spec(self) -> str:
        types = [f"{param} :: {self.arg_type(arg)}" for param, arg in zip(self.params, self.args)]
        types.append(f"Result :: {self.result_type()}")
        return f"{self.nif_name}({', '.join(self.params)}) -> Result when {', '.join(types)}"

    @property
    def doc(self) -> str:
        return self.schema.doc.strip()

    @property
    def public(self) -> list["PublicFunction"]:
        variants = self.schema.erlang or [schema.ErlangVariant(params=self.params)]
        functions = []
        for variant in variants:
            args = variant.args if variant.args is not None else list(variant.params)
            types = {}
            for param in variant.params:
                if param in args:
                    types[param] = self.arg_type(self.args[args.index(param)], local=True)
                else:
                    types[param] = "dynamic()"
            functions.append(
                PublicFunction(
                    name=self.name,
                    params=list(variant.params),
                    args=args,
                    types=types,
                    result_type=self.result_type(local=True),
                    doc=(variant.doc or self.doc).strip(),
                    target=self,
                    deprecated=self.schema.deprecated,
                )
            )
        return functions


@dataclass
class PublicFunction:
    name: str
    params: list[str]
    args: list[str]
    types: dict[str, str]
    result_type: str
    doc: str
    target: ConstantCtx | FunctionCtx = field(repr=False)
    expression: str | None = None
    deprecated: str | None = None

    @property
    def arity(self) -> int:
        return len(self.params)

    @property
    def atom(self) -> str:
        return erlang_atom(self.name)

    @property
    def spec(self) -> str:
        types = [f"{param} :: {self.types[param]}" for param in self.params]
        types.append(f"Result :: {self.result_type}")
        return f"{self.atom}({', '.join(self.params)}) -> Result when {', '.join(types)}"

    @property
    def body(self) -> str:
        if self.expression is not None:
            return " ".join(self.expression.split())
        return f"libsodium_nif:{self.target.nif_name}({', '.join(self.args)})"


@dataclass
class NamespaceCtx:
    ctx: "Context" = field(repr=False)
    name: str
    schema: schema.Namespace

    @property
    def module(self) -> str:
        return self.schema.module or f"libsodium_{self.name}"

    @property
    def group(self) -> str:
        return namespace_group(self.name)

    @property
    def state_c_type(self) -> str | None:
        for function in self.schema.functions:
            for item in [*function.args, *function.outputs]:
                if isinstance(item, (schema.StateArg, schema.StateOutput)):
                    return item.c_type
        return None

    @property
    def c_prefix(self) -> str:
        return {"utils": "sodium", "runtime": "sodium_runtime"}.get(self.name, self.name)

    @property
    def title(self) -> str:
        return self.schema.title

    @property
    def doc(self) -> str:
        return self.schema.doc.strip()

    @property
    def example(self) -> str | None:
        return self.schema.example.strip() if self.schema.example else None

    @property
    def tests(self) -> list[tuple[str, str]]:
        cases = []
        if any(constant.schema.value is not None for constant in self.constants):
            cases.append((f"{self.name}_constants", self.constants_test))
        if self.example:
            cases.append((f"{self.name}_example", self.example.rstrip().removesuffix(".")))
        for test in self.schema.tests:
            cases.append((f"{self.name}_{test.name}", test.code.strip().rstrip().removesuffix(".")))
        return cases

    @property
    def constants_test(self) -> str:
        checks = []
        for constant in self.constants:
            value = constant.schema.value
            if value is None:
                continue
            if constant.schema.type == "string":
                expected = f'<<"{value}">>'
            else:
                expected = str(value)
            checks.append(f"{expected} = {self.module}:{constant.name}()")
        return ",\n".join(checks)

    @cached_property
    def constants(self) -> list[ConstantCtx]:
        return [ConstantCtx(self, constant) for constant in self.schema.constants if constant.type != "erlang"]

    @cached_property
    def erlang_constants(self) -> list[ConstantCtx]:
        return [ConstantCtx(self, constant) for constant in self.schema.constants if constant.type == "erlang"]

    @cached_property
    def functions(self) -> list[FunctionCtx]:
        return [FunctionCtx(self, function) for function in self.schema.functions]

    @property
    def nif_functions(self) -> list[ConstantCtx | FunctionCtx]:
        return sorted([*self.constants, *self.functions], key=lambda f: (f.nif_name, f.arity))

    @property
    def public_functions(self) -> list[PublicFunction]:
        functions = [constant.public for constant in [*self.constants, *self.erlang_constants]]
        for function in self.functions:
            functions += function.public
        return sorted(functions, key=lambda f: (f.name, f.arity))

    @property
    def update_functions(self) -> list[FunctionCtx]:
        return [function for function in self.functions if function.is_update]

    @property
    def deprecated_functions(self) -> list[PublicFunction]:
        return [function for function in self.public_functions if function.deprecated]
