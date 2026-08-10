#!/usr/bin/env python3
"""Regression self-test for the scripts/README.md line-count renderer."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts/render-scripts-readme-counts.py"


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected: str
    actual: str
    passed: bool


def load_renderer_module() -> Any:
    spec = importlib.util.spec_from_file_location("render_scripts_readme_counts", RENDERER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {RENDERER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def lines(*items: str) -> str:
    return "\n".join(items) + "\n"


def base_script_files() -> dict[str, bytes]:
    return {
        "scripts/with-final-newline.py": b"print('one')\nprint('two')\n",
        "scripts/no-final-newline.sh": b"#!/bin/sh\nprintf no-final-newline",
        "scripts/single-line-no-newline.py": b"print('solo')",
        "scripts/empty.sh": b"",
        "scripts/sub/dir/name.sh": b"alpha\nbeta\ngamma\n",
        "scripts/other/name.sh": b"wrong\nwrong\nwrong\nwrong\n",
        "scripts/nested/fallback.sh": b"fallback\n",
    }


def readme_fixture(counts: dict[str, int]) -> str:
    def count(display: str) -> int:
        return counts[display]

    return lines(
        "# fixture",
        "",
        "Talos host firewall keeps apid (50000) + trustd (50001) reachable.",
        "",
        "| Script (lines) | Protects | Native alternative | Verdict |",
        "|---|---|---|---|",
        f"| `with-final-newline.py` ({count('with-final-newline.py')}) | fixture | none | KEEP |",
        f"| `no-final-newline.sh` ({count('no-final-newline.sh')}) | fixture | none | KEEP |",
        f"| `single-line-no-newline.py` ({count('single-line-no-newline.py')}) | fixture | none | KEEP |",
        f"| `empty.sh` ({count('empty.sh')}) | fixture | none | KEEP |",
        f"| `sub/dir/name.sh` ({count('sub/dir/name.sh')}) | fixture | none | KEEP |",
        f"| `fallback.sh` ({count('fallback.sh')}) | fixture | none | KEEP |",
    )


def current_counts() -> dict[str, int]:
    return {
        "with-final-newline.py": 2,
        "no-final-newline.sh": 1,
        "single-line-no-newline.py": 0,
        "empty.sh": 0,
        "sub/dir/name.sh": 3,
        "fallback.sh": 1,
    }


def stale_counts() -> dict[str, int]:
    return {
        "with-final-newline.py": 99,
        "no-final-newline.sh": 99,
        "single-line-no-newline.py": 99,
        "empty.sh": 99,
        "sub/dir/name.sh": 99,
        "fallback.sh": 99,
    }


def write_file(root: Path, relpath: str, data: bytes) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(root: Path, relpath: str, text: str) -> None:
    write_file(root, relpath, text.encode("utf-8"))


def write_fixture(root: Path, counts: dict[str, int]) -> None:
    for relpath, data in base_script_files().items():
        write_file(root, relpath, data)
    write_text(root, "scripts/README.md", readme_fixture(counts))


def assert_equal(actual: object, expected: object, detail: str) -> None:
    if actual != expected:
        raise AssertionError(f"{detail}: expected {expected!r}, got {actual!r}")


def assert_contains(haystack: str, needle: str, detail: str) -> None:
    if needle not in haystack:
        raise AssertionError(f"{detail}: missing {needle!r} in {haystack!r}")


def assert_not_contains(haystack: str, needle: str, detail: str) -> None:
    if needle in haystack:
        raise AssertionError(f"{detail}: unexpected {needle!r} in {haystack!r}")


def capture_main(renderer: Any, root: Path, argv: Sequence[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = renderer.main(argv, root=root)
    return rc, stdout.getvalue(), stderr.getvalue()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_wc_line_count_semantics(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-wc-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(root, current_counts())
        cases = {
            "scripts/with-final-newline.py": 2,
            "scripts/no-final-newline.sh": 1,
            "scripts/single-line-no-newline.py": 0,
            "scripts/empty.sh": 0,
        }
        for relpath, expected in cases.items():
            assert_equal(renderer.wc_line_count(root / relpath), expected, relpath)


def check_default_render_updates_only_anchored_counts(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-render-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(root, stale_counts())
        rc, stdout, stderr = capture_main(renderer, root, [])
        assert_equal(rc, 0, "default render rc")
        assert_contains(stdout, "wrote scripts/README.md (6 rows)", "default render stdout")
        assert_equal(stderr, "", "default render stderr")

        rendered = (root / "scripts/README.md").read_text(encoding="utf-8")
        assert_contains(rendered, "`with-final-newline.py` (2)", "with-final-newline count")
        assert_contains(rendered, "`no-final-newline.sh` (1)", "no-final-newline count")
        assert_contains(rendered, "`single-line-no-newline.py` (0)", "single-line no newline count")
        assert_contains(rendered, "`empty.sh` (0)", "empty count")
        assert_contains(rendered, "`sub/dir/name.sh` (3)", "path-prefixed literal row")
        assert_contains(rendered, "`fallback.sh` (1)", "basename fallback row")
        assert_contains(rendered, "apid (50000) + trustd (50001)", "prose port numbers")
        assert_not_contains(rendered, "(99)", "stale counts")


def check_check_mode(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-current-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(root, current_counts())
        readme = root / "scripts/README.md"
        before_hash = file_hash(readme)
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 0, "current --check rc")
        assert_contains(stdout, "match script wc -l sources (6 rows)", "current --check stdout")
        assert_equal(stderr, "", "current --check stderr")
        assert_equal(file_hash(readme), before_hash, "current --check must not write")

    with tempfile.TemporaryDirectory(prefix="readme-counts-stale-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(root, stale_counts())
        readme = root / "scripts/README.md"
        stale_hash = file_hash(readme)
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 1, "stale --check rc")
        assert_equal(stdout, "", "stale --check stdout")
        assert_contains(stderr, "line counts are stale", "stale --check stderr")
        assert_contains(stderr, "--- scripts/README.md (current)", "stale diff")
        assert_contains(stderr, "+++ scripts/README.md (expected)", "stale diff")
        assert_equal(file_hash(readme), stale_hash, "stale --check must not write")


def check_padded_parens_are_managed(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-padded-parens-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(root, current_counts())
        readme = root / "scripts/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(
                "`with-final-newline.py` (2)",
                "`with-final-newline.py` ( 999 )",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )

        padded_hash = file_hash(readme)
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 1, "padded stale --check rc")
        assert_equal(stdout, "", "padded stale --check stdout")
        assert_contains(stderr, "line counts are stale", "padded stale --check stderr")
        assert_contains(stderr, "-| `with-final-newline.py` ( 999 )", "padded stale current diff")
        assert_contains(stderr, "+| `with-final-newline.py` (2)", "padded stale expected diff")
        assert_equal(file_hash(readme), padded_hash, "padded stale --check must not write")

        rc, stdout, stderr = capture_main(renderer, root, [])
        assert_equal(rc, 0, "padded render rc")
        assert_contains(stdout, "wrote scripts/README.md (6 rows)", "padded render stdout")
        assert_equal(stderr, "", "padded render stderr")

        rendered = readme.read_text(encoding="utf-8")
        assert_contains(rendered, "`with-final-newline.py` (2)", "padded canonical count")
        assert_not_contains(rendered, "`with-final-newline.py` ( 999 )", "padded stale count")


def check_zero_rows_exits_2(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-zero-") as tmpdir:
        root = Path(tmpdir)
        for relpath, data in base_script_files().items():
            write_file(root, relpath, data)
        write_text(root, "scripts/README.md", readme_fixture(current_counts()).replace("| `", "|  `"))

        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "zero rows --check rc")
        assert_equal(stdout, "", "zero rows stdout")
        assert_contains(stderr, "ERROR:", "zero rows stderr")
        assert_contains(stderr, "manifest table format is unrecognised", "zero rows format error")
        assert_contains(stderr, "no `name` (N) rows found", "zero rows invariant")


def check_fenced_rows_untouched(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-fence-") as tmpdir:
        root = Path(tmpdir)
        for relpath, data in base_script_files().items():
            write_file(root, relpath, data)
        fenced_block = lines(
            "```markdown",
            "| `with-final-newline.py` (888) | fenced | none | KEEP |",
            "```",
        )
        write_text(
            root,
            "scripts/README.md",
            lines(
                "# fixture",
                "",
                "| Script (lines) | Protects | Native alternative | Verdict |",
                "|---|---|---|---|",
                "| `with-final-newline.py` (99) | fixture | none | KEEP |",
                "",
            )
            + fenced_block,
        )

        rc, stdout, stderr = capture_main(renderer, root, [])
        assert_equal(rc, 0, "fenced render rc")
        assert_contains(stdout, "wrote scripts/README.md (1 rows)", "fenced render stdout")
        assert_equal(stderr, "", "fenced render stderr")

        rendered = (root / "scripts/README.md").read_text(encoding="utf-8")
        assert_contains(rendered, "| `with-final-newline.py` (2) | fixture | none | KEEP |", "real row updated")
        assert_not_contains(rendered, "| `with-final-newline.py` (99) | fixture | none | KEEP |", "real row stale count")
        assert_contains(rendered, fenced_block, "fenced row byte-identical")


def check_unbalanced_fence_exits_2(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-unclosed-fence-") as tmpdir:
        root = Path(tmpdir)
        for relpath, data in base_script_files().items():
            write_file(root, relpath, data)
        write_text(
            root,
            "scripts/README.md",
            lines(
                "# fixture",
                "",
                "| Script (lines) | Protects | Native alternative | Verdict |",
                "|---|---|---|---|",
                "| `with-final-newline.py` (2) | fixture | none | KEEP |",
                "```markdown",
                "| `no-final-newline.sh` (99) | fixture | none | KEEP |",
            ),
        )

        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "unbalanced fence --check rc")
        assert_equal(stdout, "", "unbalanced fence stdout")
        assert_contains(stderr, "ERROR:", "unbalanced fence stderr")
        assert_contains(stderr, "unclosed code fence", "unbalanced fence invariant")


def check_partial_reformat_exits_2(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-partial-reformat-") as tmpdir:
        root = Path(tmpdir)
        write_fixture(root, current_counts())
        readme = root / "scripts/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(
                "| `with-final-newline.py` (2)",
                "|  `with-final-newline.py` (99)",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )

        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "partial reformat --check rc")
        assert_equal(stdout, "", "partial reformat stdout")
        assert_contains(stderr, "ERROR:", "partial reformat stderr")
        assert_contains(
            stderr,
            "row(s) look like manifest entries but did not match the expected cell format",
            "partial reformat invariant",
        )
        assert_contains(stderr, "line 7: |  `with-final-newline.py` (99)", "partial reformat offender")


def check_resolution_errors(renderer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix="readme-counts-unresolved-") as tmpdir:
        root = Path(tmpdir)
        write_text(
            root,
            "scripts/README.md",
            lines(
                "| Script (lines) | Protects | Native alternative | Verdict |",
                "|---|---|---|---|",
                "| `missing.py` (1) | fixture | none | KEEP |",
            ),
        )
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "unresolved rc")
        assert_equal(stdout, "", "unresolved stdout")
        assert_contains(stderr, "ERROR:", "unresolved stderr")
        assert_contains(stderr, "missing.py", "unresolved offender")

    with tempfile.TemporaryDirectory(prefix="readme-counts-ambiguous-") as tmpdir:
        root = Path(tmpdir)
        write_file(root, "scripts/a/dup.sh", b"a\n")
        write_file(root, "scripts/b/dup.sh", b"b\n")
        write_text(
            root,
            "scripts/README.md",
            lines(
                "| Script (lines) | Protects | Native alternative | Verdict |",
                "|---|---|---|---|",
                "| `dup.sh` (1) | fixture | none | KEEP |",
            ),
        )
        rc, stdout, stderr = capture_main(renderer, root, ["--check"])
        assert_equal(rc, 2, "ambiguous rc")
        assert_equal(stdout, "", "ambiguous stdout")
        assert_contains(stderr, "ERROR:", "ambiguous stderr")
        assert_contains(stderr, "ambiguous script name 'dup.sh'", "ambiguous offender")


def run_case(name: str, func: Callable[[], None]) -> CaseResult:
    try:
        func()
    except Exception as exc:
        return CaseResult(name, "pass", repr(exc), False)
    return CaseResult(name, "pass", "pass", True)


def print_table(results: Sequence[CaseResult]) -> None:
    name_width = max(len("case"), *(len(result.name) for result in results))
    print(f"{'case':<{name_width}}  expected  result")
    print(f"{'-' * name_width}  --------  ------")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"{result.name:<{name_width}}  {result.expected:<8}  {status}")
        if not result.passed:
            print(f"  actual: {result.actual}")


def check_coverage_requires_a_real_row(renderer: Any) -> None:
    """A guard with NO manifest row must fail — and a PROSE mention must not satisfy it.

    The first version of this coverage check substring-searched the whole rendered
    document, so a sentence merely naming a guard counted as coverage while a legitimate
    "./check-x.py" row did not. These cases pin both directions.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, current_counts())
        write_file(root, "scripts/check-unlisted.py", b"print('guard')\n")
        try:
            renderer.render_readme(root)
        except renderer.RenderError as exc:
            assert_contains(str(exc), "MISSING a row for: check-unlisted.py", "missing-row message")
        else:
            raise AssertionError("a guard with no manifest row was accepted")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, current_counts())
        write_file(root, "scripts/check-unlisted.py", b"print('guard')\n")
        readme = root / "scripts" / "README.md"
        write_text(root, "scripts/README.md", readme.read_text() + "\nSee `check-unlisted.py` for details.\n")
        try:
            renderer.render_readme(root)
        except renderer.RenderError as exc:
            assert_contains(str(exc), "check-unlisted.py", "prose mention must not count as a row")
        else:
            raise AssertionError("a prose mention was accepted as manifest coverage")


def check_coverage_accepts_path_prefixed_rows(renderer: Any) -> None:
    """A row citing "./check-x.py" or a nested path is real coverage (basename identity)."""
    for display in ("./check-pathy.py", "sub/dir/check-pathy.py"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, current_counts())
            write_file(root, "scripts/check-pathy.py", b"print('guard')\n")
            readme = (root / "scripts" / "README.md").read_text()
            row = f"| `{display}` (1) | fixture | none | KEEP |\n"
            write_text(root, "scripts/README.md", readme + row)
            renderer.render_readme(root)  # must not raise


def check_coverage_ignores_selftests(renderer: Any) -> None:
    """A guard's .selftest.py needs no row of its own."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, current_counts())
        write_file(root, "scripts/check-covered.py", b"print('g')\n")
        write_file(root, "scripts/check-covered.selftest.py", b"print('s')\n")
        readme = (root / "scripts" / "README.md").read_text()
        write_text(root, "scripts/README.md", readme + "| `check-covered.py` (1) | fixture | none | KEEP |\n")
        renderer.render_readme(root)  # must not raise


def main() -> int:
    try:
        renderer = load_renderer_module()
    except Exception as exc:
        print(f"SELFTEST FAIL: {exc}", file=sys.stderr)
        return 1

    checks: Sequence[tuple[str, Callable[[], None]]] = (
        ("wc line-count semantics", lambda: check_wc_line_count_semantics(renderer)),
        ("anchored count rendering", lambda: check_default_render_updates_only_anchored_counts(renderer)),
        ("check mode exits and no-write", lambda: check_check_mode(renderer)),
        ("padded parens are managed", lambda: check_padded_parens_are_managed(renderer)),
        ("zero rows exits 2", lambda: check_zero_rows_exits_2(renderer)),
        ("fenced rows untouched", lambda: check_fenced_rows_untouched(renderer)),
        ("unbalanced fence exits 2", lambda: check_unbalanced_fence_exits_2(renderer)),
        ("partial reformat exits 2", lambda: check_partial_reformat_exits_2(renderer)),
        ("resolution error exits", lambda: check_resolution_errors(renderer)),
        ("coverage requires a real row", lambda: check_coverage_requires_a_real_row(renderer)),
        ("coverage accepts path-prefixed rows", lambda: check_coverage_accepts_path_prefixed_rows(renderer)),
        ("coverage ignores selftests", lambda: check_coverage_ignores_selftests(renderer)),
    )
    results = [run_case(name, func) for name, func in checks]

    print_table(results)
    failures = [result for result in results if not result.passed]
    if failures:
        print("\nSELFTEST FAIL", file=sys.stderr)
        for failure in failures:
            print(f"{failure.name}: {failure.actual}", file=sys.stderr)
        return 1

    print("\nSELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
