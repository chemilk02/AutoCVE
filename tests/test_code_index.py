from autocve.inventory.code_index import (
    index_repository,
    is_test_path,
    js_imports,
    python_imports,
)


def test_python_imports_top_level_only():
    source = (
        "import os.path\nimport yaml, requests as r\nfrom django.db import models\n"
        "from . import x\n"
    )
    assert python_imports(source) == ["django", "os", "requests", "yaml"]


def test_python_syntax_error_returns_empty():
    assert python_imports("def broken(:\n") == []


def test_js_imports_cover_common_forms():
    source = """
    import express from 'express';
    import { a, b } from "@scope/pkg/sub/path";
    import * as _ from 'lodash';
    import 'side-effect';
    const qs = require('qs');
    const lazy = await import("lazy-pkg");
    export { thing } from 'reexport';
    import local from './local';
    import fs from 'fs';
    import path from 'node:path';
    """
    assert js_imports(source) == [
        "@scope/pkg",
        "express",
        "lazy-pkg",
        "lodash",
        "qs",
        "reexport",
        "side-effect",
    ]


def test_test_path_detection():
    assert is_test_path("tests/test_app.py")
    assert is_test_path("src/__tests__/a.js")
    assert is_test_path("src/a.test.ts")
    assert is_test_path("pkg/app_test.py")
    assert not is_test_path("src/app.py")
    assert not is_test_path("src/contest.js")


def test_index_repository(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("import flask\n")
    (tmp_path / "src" / "index.ts").write_text("import axios from 'axios'\n")
    (tmp_path / "src" / "types.d.ts").write_text("import x from 'ignored'\n")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "index.js").write_text("require('nope')\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("import pytest\n")

    files = {f.path: f for f in index_repository(tmp_path)}
    assert set(files) == {"src/app.py", "src/index.ts", "tests/test_app.py"}
    assert files["src/app.py"].imports == ["flask"]
    assert files["src/index.ts"].imports == ["axios"]
    assert files["tests/test_app.py"].is_test
    assert len(files["src/app.py"].sha256) == 64
