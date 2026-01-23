# scripts/function_coverage_report.py
import json, inspect, importlib, pkgutil, sys
from pathlib import Path
from types import ModuleType
from typing import Dict, Set, Tuple

PKGS = ["modbus", "capture", "pipeline", "mqtt", "cli"]  # adjust as needed
COVER_JSON = Path("coverage.json")

def load_covered_lines() -> Dict[Path, Set[int]]:
    data = json.loads(COVER_JSON.read_text(encoding="utf-8"))
    files = data.get("files", {})
    covered_by_file: Dict[Path, Set[int]] = {}
    for path_str, info in files.items():
        executed = set(info.get("executed_lines", []))
        if executed:
            covered_by_file[Path(path_str).resolve()] = executed
    return covered_by_file

def walk_modules(pkg_name: str):
    try:
        pkg_mod = importlib.import_module(pkg_name)
    except Exception as e:
        print(f"# SKIP package {pkg_name}: {e}", file=sys.stderr)
        return
    if not hasattr(pkg_mod, "__path__"):
        # single-file module; still report
        yield pkg_mod
        return
    for m in pkgutil.walk_packages(pkg_mod.__path__, pkg_name + "."):
        name = m.name
        try:
            mod = importlib.import_module(name)
            yield mod
        except Exception as e:
            print(f"# SKIP module {name}: {e}", file=sys.stderr)

def functions_in_module(mod: ModuleType):
    funcs = []
    for name, obj in inspect.getmembers(mod, inspect.isfunction):
        if name.startswith("_"):
            continue
        if getattr(obj, "__module__", "") != mod.__name__:
            continue
        try:
            src_file = Path(inspect.getsourcefile(obj)).resolve()
            src_lines, start = inspect.getsourcelines(obj)
            end = start + len(src_lines) - 1
            funcs.append((name, src_file, start, end))
        except Exception as e:
            # builtins, C-extensions, or dynamically created
            continue
    return funcs

def covered_any(covered: Dict[Path, Set[int]], src_file: Path, start: int, end: int) -> bool:
    lines = covered.get(src_file, set())
    # If ANY line in the function body executed, count as covered
    return any((ln in lines) for ln in range(start, end + 1))

def main():
    if not COVER_JSON.exists():
        print("coverage.json not found. Run:\n"
              "  coverage run -m pytest -m unit\n"
              "  coverage json -o coverage.json\n", file=sys.stderr)
        sys.exit(2)

    covered = load_covered_lines()
    rows: Dict[str, Dict[str, Tuple[Path, int, int, bool]]] = {}

    for pkg in PKGS:
        for mod in walk_modules(pkg):
            mod_funcs = functions_in_module(mod)
            if not mod_funcs:
                continue
            modname = mod.__name__
            rows.setdefault(modname, {})
            for fname, src_file, start, end in mod_funcs:
                is_cov = covered_any(covered, src_file, start, end)
                rows[modname][fname] = (src_file, start, end, is_cov)

    # Pretty print
    total = tested = 0
    for modname in sorted(rows.keys()):
        print(f"\n[{modname}]")
        for fname in sorted(rows[modname].keys()):
            src_file, start, end, is_cov = rows[modname][fname]
            mark = "Y" if is_cov else "X"
            print(f"  {mark} {fname}  ({src_file.name}:{start}-{end})")
            total += 1
            if is_cov:
                tested += 1

    print(f"\nSummary: {tested}/{total} functions covered by unit tests "
          f"({(tested/total*100 if total else 0):.1f}%).")

if __name__ == "__main__":
    main()
