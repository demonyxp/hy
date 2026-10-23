"""在已安装的隔离容器验证安装入口校验及重复执行，不访问远端发布地址。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

if os.environ.get("HY_DISPOSABLE_TEST") != "1" or not Path("/.dockerenv").exists():
    raise SystemExit("仅允许在一次性 Docker 测试容器中运行。")

source = Path(__file__).parents[1]
state = Path("/etc/hy/state.json")
manager = Path("/usr/local/lib/hy/hy.py")
before = state.read_bytes()
pid = subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", "hy-server"])
with tempfile.TemporaryDirectory(prefix="hy-bootstrap-") as tmp:
    root = Path(tmp)
    binary = root / "bin"
    binary.mkdir()
    curl = binary / "curl"
    curl.write_text('''#!/usr/bin/python3
import os,sys,shutil
from pathlib import Path
url = next(arg for arg in sys.argv if arg.startswith("https://"))
name = url.rsplit("/", 1)[1]
assert name in ("hy.py", "release.json")
shutil.copyfile(Path(os.environ["HY_BOOTSTRAP_SOURCE"]) / name, sys.argv[sys.argv.index("-o") + 1])
''')
    curl.chmod(0o755)
    content = (source / "hy.py").read_bytes()
    (root / "hy.py").write_bytes(content)
    env = {**os.environ, "PATH": str(binary) + ":" + os.environ["PATH"], "HY_BOOTSTRAP_SOURCE": str(root)}
    valid = json.loads((source / "release.json").read_text())
    for metadata, candidate in (({**valid, "sha256": "0" * 64}, content),
                                ({**valid, "version": "0.0.0"}, content),
                                ({**valid, "sha256": hashlib.sha256(b"if broken").hexdigest()}, b"if broken"),
                                (valid, content)):
        (root / "hy.py").write_bytes(candidate)
        (root / "release.json").write_text(json.dumps(metadata))
        old_manager = manager.read_bytes()
        result = subprocess.run(["bash", str(source / "install.sh")], env=env, capture_output=True, timeout=20)
        success = metadata == valid and candidate == content
        assert (result.returncode == 0) == success, result.stderr.decode()
        assert manager.read_bytes() == (content if success else old_manager)
        assert state.read_bytes() == before
        assert pid == subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", "hy-server"])
print("PASS: bootstrap checksum / version / syntax rejection and successful repeat install preserve config and PID")
