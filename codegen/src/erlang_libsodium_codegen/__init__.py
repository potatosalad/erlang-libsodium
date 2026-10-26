"""Generate C and Erlang code from YAML configuration using Jinja2."""

from .code_generator import CodeGenerator
from .schema import Root

__all__ = ["CodeGenerator", "Root"]
