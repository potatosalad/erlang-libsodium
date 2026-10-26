"""Template context for libsodium code generation."""

from dataclasses import dataclass, field
from functools import cached_property

from ..schema import Root
from .api import GROUPS, ConstantCtx, FunctionCtx, NamespaceCtx, PublicFunction
from .nif import NIF

__all__ = ["ConstantCtx", "Context", "FunctionCtx", "NamespaceCtx", "PublicFunction"]


@dataclass
class Context:
    _output_path: str = field(repr=False)
    schema: Root = field(repr=False)
    nif: NIF = field(init=False)

    def __post_init__(self) -> None:
        self.reset_atoms()

    def reset_atoms(self) -> None:
        self.nif = NIF()
        for name in self.schema.nif.atoms:
            self.nif.make_atom(name)

    @cached_property
    def namespaces(self) -> list[NamespaceCtx]:
        return [NamespaceCtx(self, name, namespace) for name, namespace in sorted(self.schema.namespaces.items())]

    @property
    def groups(self) -> list[tuple[str, list[NamespaceCtx]]]:
        groups = []
        for group, _ in GROUPS:
            members = [namespace for namespace in self.namespaces if namespace.group == group]
            if members:
                groups.append((group, members))
        return groups

    @property
    def nif_functions(self) -> list[ConstantCtx | FunctionCtx]:
        functions = [function for namespace in self.namespaces for function in namespace.nif_functions]
        return sorted(functions, key=lambda f: (f.nif_name, f.arity))

    @property
    def state_types(self) -> list[str]:
        return sorted({namespace.state_c_type for namespace in self.namespaces if namespace.state_c_type})

    @property
    def update_functions(self) -> list[FunctionCtx]:
        return [function for namespace in self.namespaces for function in namespace.update_functions]

    @property
    def test_groups(self) -> list[tuple[str, list[tuple[str, str]]]]:
        return [(namespace.name, namespace.tests) for namespace in self.namespaces if namespace.tests]

    @property
    def test_cases(self) -> list[str]:
        return sorted(name for _, cases in self.test_groups for name, _ in cases)

    @property
    def dirty_threshold(self) -> int:
        return self.schema.nif.dirty_threshold

    @property
    def update_chunk(self) -> int:
        return self.schema.nif.update_chunk
