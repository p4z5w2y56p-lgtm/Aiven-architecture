"""The zips of the functions (ruling R110; infra/terraform/modules/control/functions.tf).

Terraform zips each function from the repository: main.py, the aiven modules it imports, and
requirements.txt. These tests keep the two lists in functions.tf and the pins in requirements.txt in
step with the code, so a zip never misses a module and never runs a library that uv.lock does not
pin.
"""

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.support import REPO_ROOT

SRC = REPO_ROOT / "src"
FUNCTIONS_TF = REPO_ROOT / "infra" / "terraform" / "modules" / "control" / "functions.tf"
REQUIREMENTS = SRC / "aiven" / "functions" / "requirements.txt"
EXPORT = ["export", "--frozen", "--only-group", "functions", "--no-emit-project", "--no-annotate"]


def terraform_lists() -> tuple[list[str], dict[str, str]]:
    """`function_modules` and `functions` as functions.tf has them."""
    text = FUNCTIONS_TF.read_text(encoding="utf-8")
    (modules,) = re.findall(r"function_modules = \[(.*?)\]", text, re.DOTALL)
    (functions,) = re.findall(r"functions = \{(.*?)\}", text, re.DOTALL)
    return re.findall(r'"([^"]+)"', modules), dict(re.findall(r'"([^"]+)" = "([^"]+)"', functions))


def module_file(name: str) -> Path | None:
    """The file of module `name` under src, or None when there is none."""
    path = SRC.joinpath(*name.split("."))
    if path.with_suffix(".py").is_file():
        return path.with_suffix(".py")
    if (path / "__init__.py").is_file():
        return path / "__init__.py"
    return None


def aiven_imports(path: Path) -> set[str]:
    """The aiven modules that a file imports, wherever the import stands in it."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names if alias.name.startswith("aiven"))
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("aiven"):
            found.add(node.module)
            # `from aiven.common import audit` imports a module as a name.
            found.update(
                f"{node.module}.{alias.name}"
                for alias in node.names
                if module_file(f"{node.module}.{alias.name}") is not None
            )
    return found


def closure(module: str) -> set[str]:
    """Every file under src that `from <module> import main` loads, as main.py does it: the module,
    the packages on its way, and the same for each aiven module that one of them imports."""
    files: set[Path] = set()
    parts = module.split(".")
    todo = [module_file(".".join(parts[:depth])) for depth in range(1, len(parts) + 1)]
    while todo:
        path = todo.pop()
        if path in files:
            continue
        files.add(path)
        for name in aiven_imports(path):
            parts = name.split(".")
            for depth in range(1, len(parts) + 1):  # each package on the way loads its __init__
                found = module_file(".".join(parts[:depth]))
                assert found is not None, name
                todo.append(found)
    return {path.relative_to(SRC).as_posix() for path in files}


def test_each_zip_holds_exactly_the_modules_its_function_imports():
    common, functions = terraform_lists()
    assert functions
    for name, module in functions.items():
        dotted = module.removesuffix(".py").replace("/", ".")
        assert closure(dotted) == set(common) | {module}, name


def test_each_function_module_has_an_entry_point_main():
    _, functions = terraform_lists()
    for module in functions.values():
        tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
        names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
        assert "main" in names, module


def test_no_zip_carries_the_yaml_library_or_the_validator():
    common, functions = terraform_lists()
    for path in [*common, *functions.values()]:
        text = (SRC / path).read_text(encoding="utf-8")
        assert "ruamel" not in text and "markdown_it" not in text, path


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv, as CI has")
def test_requirements_are_the_functions_group_of_uv_lock_with_hashes():
    done = subprocess.run(
        ["uv", *EXPORT], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    exported = [line for line in done.stdout.splitlines() if not line.startswith("#")]
    committed = [
        line
        for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
        if not line.startswith("#")
    ]
    assert committed == exported, (
        "run: uv " + " ".join(EXPORT) + " -o " + str(REQUIREMENTS.relative_to(REPO_ROOT))
    )


def test_every_requirement_is_pinned_with_hashes():
    text = REQUIREMENTS.read_text(encoding="utf-8")
    requirements = re.findall(r"^([A-Za-z0-9_.-]+)==([^ ;\\]+)", text, re.MULTILINE)
    assert len(requirements) >= 3
    names = {name.lower() for name, _ in requirements}
    assert {"functions-framework", "google-cloud-billing", "google-cloud-logging"} <= names
    for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text.split("\n", 2)[2]):
        assert "--hash=sha256:" in block, block.splitlines()[0]
