from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from erlang_libsodium_codegen.code_generator import TOKEN, load_config, sign_source
from erlang_libsodium_codegen.context import Context
from erlang_libsodium_codegen.schema import Function, Namespace, Root

ROOT = Path(__file__).resolve().parents[1]


def context(namespaces: dict) -> Context:
    return Context(_output_path=".", schema=Root.model_validate({"namespaces": namespaces}))


def namespace(**functions) -> dict:
    return {"title": "Example", "doc": "Example.", "functions": list(functions.values())}


def test_repository_configuration_is_valid():
    schema = load_config(str(ROOT / "config.yaml"))
    assert "crypto_generichash" in schema.namespaces
    ctx = Context(_output_path=".", schema=schema)
    names = [(f.nif_name, f.arity) for f in ctx.nif_functions]
    assert names == sorted(names)
    assert len(names) == len(set(names))


def test_duplicate_namespaces_are_rejected(tmp_path):
    (tmp_path / "config.yaml").write_text("nif: {}\n")
    (tmp_path / "namespaces").mkdir()
    definition = {"crypto_example": {"title": "Example", "doc": "Example."}}
    (tmp_path / "namespaces" / "a.yaml").write_text(yaml.safe_dump(definition))
    (tmp_path / "namespaces" / "b.yaml").write_text(yaml.safe_dump(definition))
    with pytest.raises(ValueError, match="already defined"):
        load_config(str(tmp_path / "config.yaml"))


def test_signature_is_stable():
    unsigned = f"// @generated {TOKEN}\nint x;\n".encode()
    signed = sign_source(unsigned)
    assert TOKEN.encode() not in signed
    assert sign_source(signed) == signed
    assert sign_source(b"no token") == b"no token"


def test_default_call_places_outputs_first():
    ctx = context(
        {
            "crypto_example": namespace(
                easy={
                    "name": "easy",
                    "doc": "Encrypt.",
                    "args": [
                        {"type": "binary", "name": "m"},
                        {"type": "fixed", "name": "k", "size": "32"},
                    ],
                    "outputs": [{"name": "c", "size": "mlen + 16", "len": "clen"}],
                    "returns": "c",
                }
            )
        }
    )
    function = ctx.namespaces[0].functions[0]
    assert function.call_expr == "crypto_example_easy(c, &clen, m, mlen, k)"
    assert function.schedule == "auto"
    assert function.result_type() == "binary() | -1"
    assert function.nif_spec == "crypto_example_easy(M, K) -> Result when M :: binary(), K :: binary(), Result :: binary() | -1"


def test_enum_atoms_are_registered():
    ctx = context(
        {
            "utils": namespace(
                encode={
                    "name": "encode",
                    "doc": "Encode.",
                    "args": [{"type": "enum", "name": "variant", "values": {"original": "1", "urlsafe": "5"}}],
                    "call": "variant",
                    "check": "none",
                    "returns": "int:rc",
                }
            )
        }
    )
    decode = "\n".join(ctx.namespaces[0].functions[0].decode)
    assert "ATOM(original)" in decode and "ATOM(urlsafe)" in decode
    assert {"original", "urlsafe"} <= set(ctx.nif.atoms_dict)
    assert ctx.namespaces[0].c_prefix == "sodium"


def test_variants_supply_defaults():
    ctx = context(
        {
            "crypto_example": namespace(
                encrypt={
                    "name": "encrypt",
                    "doc": "Encrypt.",
                    "args": [{"type": "binary", "name": "m"}, {"type": "binary", "name": "ad", "nullable": True}],
                    "outputs": [{"name": "c", "size": "mlen"}],
                    "returns": "c",
                    "erlang": [{"params": ["M"], "args": ["M", "<<>>"]}, {"params": ["M", "AD"]}],
                }
            )
        }
    )
    public = ctx.namespaces[0].public_functions
    assert [(f.name, f.arity) for f in public] == [("encrypt", 1), ("encrypt", 2)]
    assert public[0].body == "libsodium_nif:crypto_example_encrypt(M, <<>>)"


def test_update_functions_require_state_and_binary():
    with pytest.raises(ValidationError, match="update functions"):
        Function.model_validate(
            {
                "name": "update",
                "doc": "Update.",
                "args": [{"type": "binary", "name": "in"}],
                "update": True,
                "returns": "in",
            }
        )


def test_void_calls_cannot_check_results():
    with pytest.raises(ValidationError, match="void calls"):
        Function.model_validate({"name": "keygen", "doc": "Keygen.", "rc_type": "void", "returns": "k"})


def test_duplicate_functions_are_rejected():
    function = {"name": "f", "doc": "F.", "check": "none", "returns": "int:rc"}
    with pytest.raises(ValidationError, match="Duplicate function"):
        Namespace.model_validate({"title": "T", "doc": "D.", "functions": [function, function]})


def test_reserved_words_are_quoted():
    ctx = context(
        {
            "crypto_stream": namespace(
                xor={
                    "name": "xor",
                    "doc": "XOR.",
                    "args": [{"type": "binary", "name": "m"}],
                    "outputs": [{"name": "c", "size": "mlen"}],
                    "returns": "c",
                }
            )
        }
    )
    public = ctx.namespaces[0].public_functions[0]
    assert public.atom == "'xor'"
    assert public.spec.startswith("'xor'(M) ->")
    assert ctx.namespaces[0].functions[0].nif_name == "crypto_stream_xor"


def test_states_are_resources():
    state = {"type": "state", "name": "state", "c_type": "crypto_example_state"}
    ctx = context(
        {
            "crypto_example": namespace(
                init={"name": "init", "doc": "Init.", "outputs": [state], "returns": "state"},
                update={
                    "name": "update",
                    "doc": "Update.",
                    "args": [state, {"type": "binary", "name": "in"}],
                    "update": True,
                    "returns": "state",
                },
            )
        }
    )
    namespace_ctx = ctx.namespaces[0]
    init, update = namespace_ctx.functions
    assert ctx.state_types == ["crypto_example_state"]
    assert init.result_type() == "crypto_example_state() | -1"
    assert init.result_type(local=True) == "state() | -1"
    assert update.nif_spec.startswith("crypto_example_update(State, In) -> Result when State :: crypto_example_state()")
    assert "libsodium_nif_state_make" in "\n".join(init.build_result)
    assert update.update_state_type == "libsodium_nif_state_type_crypto_example_state"


def test_namespaces_use_one_state_type():
    with pytest.raises(ValidationError, match="only one state type"):
        Namespace.model_validate(
            {
                "title": "T",
                "doc": "D.",
                "functions": [
                    {
                        "name": f"init_{c_type}",
                        "doc": "Init.",
                        "outputs": [{"type": "state", "name": "state", "c_type": c_type}],
                        "returns": "state",
                    }
                    for c_type in ("a_state", "b_state")
                ],
            }
        )
