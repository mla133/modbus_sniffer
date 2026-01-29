import re
import sys
from pathlib import Path
from collections import Counter, defaultdict

PATH_RE = re.compile(r"([A-Za-z]:\\\\[^\"',)]+)")  # crude Windows path matcher


def extract_paths(toc_text: str):
    """Extract likely file paths from a .toc file's text."""
    return PATH_RE.findall(toc_text)


def normalize(p: str) -> str:
    return p.replace("\\\\", "\\").strip()


def top_level_site_package(path: Path):
    """
    If path contains site-packages, return the top-level package folder name.
    Example:
      ...\\site-packages\\pyshark\\capture\\capture.py -> pyshark
      ...\\site-packages\\paho\\mqtt\\client.py -> paho
    """
    parts = [x.lower() for x in path.parts]
    if "site-packages" not in parts:
        return None
    i = parts.index("site-packages")
    if i + 1 >= len(parts):
        return None
    return path.parts[i + 1]


def looks_suspect(path: Path) -> bool:
    """Heuristics for stuff you usually don't want bundled."""
    low = str(path).lower()
    bad_markers = [
        "\\tests\\", "\\test\\", "\\testing\\",
        "\\docs\\", "\\doc\\", "\\examples\\", "\\example\\",
        "\\bench\\", "\\benchmark\\", "\\notebooks\\",
        "\\__pycache__\\", "\\.pytest_cache\\",
    ]
    return any(m in low for m in bad_markers)


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/analyze_toc.py <path-to-Analysis-00.toc> [optional: path-to-dist-onedir-folder]")
        sys.exit(2)

    toc_path = Path(sys.argv[1]).resolve()
    dist_dir = Path(sys.argv[2]).resolve() if len(sys.argv) >= 3 else None

    text = toc_path.read_text(encoding="utf-8", errors="ignore")
    raw_paths = [normalize(p) for p in extract_paths(text)]
    paths = [Path(p) for p in raw_paths]

    # Group counts
    pkg_counter = Counter()
    ext_counter = Counter()
    suspects = []

    # Optional: compute sizes (best with --onedir dist folder)
    bin_sizes = []  # (size, path)
    pkg_sizes = defaultdict(int)

    for p in paths:
        ext_counter[p.suffix.lower()] += 1

        pkg = top_level_site_package(p)
        if pkg:
            pkg_counter[pkg] += 1

        if looks_suspect(p):
            suspects.append(str(p))

        if dist_dir and dist_dir.exists():
            # Attempt to map original paths to the bundled file path.
            # This isn't perfect, but often works if the filename exists in dist tree.
            candidate = None
            if p.exists():
                candidate = p  # original still exists on dev machine
            else:
                # Search by filename in dist (costly but okay for one run)
                hits = list(dist_dir.rglob(p.name))
                if hits:
                    candidate = hits[0]

            if candidate and candidate.exists():
                size = candidate.stat().st_size
                # Collect only heavy native artifacts
                if candidate.suffix.lower() in (".pyd", ".dll", ".exe"):
                    bin_sizes.append((size, str(candidate)))

                if pkg:
                    pkg_sizes[pkg] += size

    # Write reports
    out_dir = toc_path.parent / "toc_reports"
    out_dir.mkdir(exist_ok=True)

    # Top packages by file count
    with (out_dir / "top_packages_by_count.txt").open("w", encoding="utf-8") as f:
        for name, count in pkg_counter.most_common(50):
            f.write(f"{name}\t{count}\n")

    # Extensions frequency
    with (out_dir / "extensions_frequency.txt").open("w", encoding="utf-8") as f:
        for ext, count in ext_counter.most_common():
            f.write(f"{ext or '<noext>'}\t{count}\n")

    # Suspects
    with (out_dir / "suspect_files.txt").open("w", encoding="utf-8") as f:
        for s in sorted(set(suspects))[:1000]:
            f.write(s + "\n")

    # Top binaries by size
    if bin_sizes:
        bin_sizes.sort(reverse=True)
        with (out_dir / "top_binaries_by_size.txt").open("w", encoding="utf-8") as f:
            for size, p in bin_sizes[:50]:
                f.write(f"{size/1024/1024:8.2f} MB\t{p}\n")

    # Top packages by total size (only if we could resolve sizes)
    if pkg_sizes:
        items = sorted(pkg_sizes.items(), key=lambda kv: kv[1], reverse=True)
        with (out_dir / "top_packages_by_size.txt").open("w", encoding="utf-8") as f:
            for name, size in items[:50]:
                f.write(f"{size/1024/1024:8.2f} MB\t{name}\n")

    print(f"Reports written to: {out_dir}")
    print("Suggested next step:")
    print("  - Look at top_packages_by_size.txt (or by_count if size unavailable)")
    print("  - Exclude obvious unused big packages (e.g., numpy/scipy/gui/test stacks) in your .spec 'excludes' list.")
    if not dist_dir:
        print("\nTip: For size-based reports, build once with --onedir and pass the dist folder:")
        print("  pyinstaller --onedir --name modbus-sniffer main.py")
        print(f"  python {toc_path.parent/'tools'/'analyze_toc.py'} {toc_path} dist/modbus-sniffer")


if __name__ == "__main__":
    main()
