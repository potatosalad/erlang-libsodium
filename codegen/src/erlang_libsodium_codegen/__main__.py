"""Command-line interface for codegen."""

import click
import json
from pathlib import Path

from pydantic import TypeAdapter

from . import CodeGenerator, Root
from .schema import Namespace


@click.group()
def main():
    """Command-line utility for codegen and schema validation."""
    pass


@main.command("generate")
@click.argument("config_file", type=click.Path(exists=True))
@click.argument("output_path", type=click.Path())
@click.argument("templates0_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.argument("templates1_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.argument("templates2_path", type=click.Path(exists=True, file_okay=False, dir_okay=True), required=False)
@click.option("--stage", type=click.Choice(["sources", "docs"]), default="sources", show_default=True)
@click.option("--check", is_flag=True, help="Verify generated documentation without changing files.")
@click.option("--library-path", type=click.Path(exists=True, file_okay=False), help="Ebin directory of the built library.")
def generate(config_file, output_path, templates0_path, templates1_path, templates2_path, stage, check, library_path):
    """Generate C and Erlang code from YAML configuration using Jinja2."""

    code_generator = CodeGenerator(config_file, output_path, templates0_path, templates1_path, templates2_path)

    if stage == "docs":
        code_generator.render_docs(check=check, library_path=library_path)
    else:
        if check or library_path:
            raise click.UsageError("--check and --library-path apply to --stage docs")
        code_generator.render()


@main.command("json-schema")
@click.argument("output_path", type=click.Path())
def json_schema(output_path: str):
    """Generate a JSON schema for the configuration file."""

    Path(output_path).write_text(json.dumps(Root.model_json_schema(), indent=2) + "\n")
    print(f"Wrote JSON schema to: {output_path}")
    namespaces_path = Path(output_path).with_name("namespace.schema.json")
    namespaces = TypeAdapter(dict[str, Namespace]).json_schema()
    namespaces_path.write_text(json.dumps(namespaces, indent=2) + "\n")
    print(f"Wrote JSON schema to: {namespaces_path}")


@main.command("sign")
@click.argument("config_file", type=click.Path(exists=True))
@click.argument("output_path", type=click.Path())
@click.argument("templates0_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.argument("templates1_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.argument("templates2_path", type=click.Path(exists=True, file_okay=False, dir_okay=True), required=False)
def sign(config_file: str, output_path: str, templates0_path: str, templates1_path: str, templates2_path):
    """Sign C and Erlang code from YAML configuration using Jinja2."""

    code_generator = CodeGenerator(config_file, output_path, templates0_path, templates1_path, templates2_path)

    code_generator.sign()


if __name__ == "__main__":
    main()  # type: ignore
