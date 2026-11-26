#!/usr/bin/env python3
"""Build the AI Agent Bridge extension into ``extension/build/burp-agent-bridge.jar``.

One build path, no Gradle, Maven or third-party runtime dependency: Python 3.8+, a JDK
(``javac`` on PATH, or a ``java`` that still carries the ``jdk.compiler`` module) and the
Montoya API jar, which Burp supplies at run time and this script only needs to compile.

    python3 extension/build.py                  compile + package
    python3 extension/build.py --test           ... then run the self-test
    python3 extension/build.py --cross-check    ... and compile a second time with ECJ
    python3 extension/build.py --check          compile only, write no jar

The Montoya API jar is looked up at ``--api-jar`` / ``$MONTOYA_API_JAR`` /
``lib/montoya-api-2026.7.jar``, and otherwise downloaded from Maven Central and verified
against the SHA-256 pinned below. Nothing downloaded ends up inside the jar.
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
SRC = HERE / "src" / "main" / "java"
BUILD = HERE / "build"
# The package's tool manifest: <repo>/aobh/tools/tools.json, resolved from this script's own location.
MANIFEST = PKG / "aobh" / "tools" / "tools.json"
MAIN_CLASS = "dev.agent.burp.standalone.StandaloneDemo"
SELF_TEST = "dev.agent.burp.selftest.SelfTest"
# Fixed timestamps make the jar byte-for-byte reproducible for the same sources.
ZIP_TIME = (2026, 1, 1, 0, 0, 0)
RELEASE = "17"
# Class-file version of Java 17 (61.0): asserted for every class that goes into the jar.
CLASS_MAJOR = 61

MAVEN = "https://repo1.maven.org/maven2"
# net.portswigger.burp.extensions:montoya-api:2026.7. The API jar's own classes are
# class-file version 61 (Java 17), so --release 17 is the highest target that makes sense.
API_VERSION = "2026.7"
API_URL = "{maven}/net/portswigger/burp/extensions/montoya-api/{v}/montoya-api-{v}.jar".format(
    maven=MAVEN, v=API_VERSION)
API_SHA256 = "cb852b7b883290fcc1d21b13d80fa10f5b13a0f57335d710d2b1e5956ecb2a94"
# org.eclipse.jdt:ecj:3.46.100, used only by --cross-check. SHA-256 computed locally from a
# copy whose SHA-1 matched the value Maven Central publishes (a06c482cdb8601a94328aae668c7236e3818fbe9).
ECJ_VERSION = "3.46.100"
ECJ_URL = "{maven}/org/eclipse/jdt/ecj/{v}/ecj-{v}.jar".format(maven=MAVEN, v=ECJ_VERSION)
ECJ_SHA256 = "74c93172475fee0cd4e6eefb44233516dd40525642da35d009146d97ea598229"


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url, dest, expected_sha256):
    """Downloads ``url`` to ``dest`` unless a copy with the pinned hash is already there."""
    if dest.exists():
        if sha256_of(dest) == expected_sha256:
            return dest
        print("  cached file has the wrong hash, downloading again: %s" % dest, file=sys.stderr)
        dest.unlink()
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    last = None
    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "agent-bridge-build/1.5"})
            with urllib.request.urlopen(req, timeout=60) as resp, open(part, "wb") as out:
                shutil.copyfileobj(resp, out)
            got = sha256_of(part)
            if got != expected_sha256:
                part.unlink()
                raise SystemExit("downloaded %s but its SHA-256 is %s, expected %s" % (url, got, expected_sha256))
            os.replace(str(part), str(dest))
            return dest
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 429:
                wait = 5 * attempt
                print("  HTTP 429 from Maven Central, retrying in %ds" % wait, file=sys.stderr)
                time.sleep(wait)
                continue
            raise SystemExit("download failed: %s -> HTTP %d" % (url, e.code))
        except urllib.error.URLError as e:
            last = e
            time.sleep(3 * attempt)
    raise SystemExit("download failed after retries: %s (%s)" % (url, last))


def find_api_jar(args):
    if args.api_jar:
        return Path(args.api_jar).resolve()
    env = os.environ.get("MONTOYA_API_JAR")
    if env:
        return Path(env).resolve()
    local = HERE / "lib" / ("montoya-api-%s.jar" % API_VERSION)
    if local.exists():
        return local
    name = "montoya-api-%s.jar" % API_VERSION
    return fetch(API_URL, Path(args.deps_dir) / ("montoya-api-" + API_VERSION) / name, API_SHA256)


def find_ecj_jar(args):
    if args.ecj_jar:
        return Path(args.ecj_jar).resolve()
    env = os.environ.get("ECJ_JAR")
    if env:
        return Path(env).resolve()
    name = "ecj-%s.jar" % ECJ_VERSION
    return fetch(ECJ_URL, Path(args.deps_dir) / ("ecj-" + ECJ_VERSION) / name, ECJ_SHA256)


def java_home(jdk):
    home = Path(jdk).resolve()
    if (home / "bin" / "java").exists():
        return home
    if home.name == "bin" and (home / "java").exists():
        return home.parent
    raise SystemExit("--jdk must point at a JDK directory: no bin/java under %s" % home)


def java_binary(jdk):
    if jdk:
        return str(java_home(jdk) / "bin" / "java")
    java = shutil.which("java")
    if not java:
        raise SystemExit("no java on PATH: install a JDK 17+ or pass --jdk <jdk-dir>")
    return java


def javac_prefix(jdk):
    """The javac command: the binary when installed, otherwise the module inside ``java``."""
    java = java_binary(jdk)
    binary = Path(java).with_name("javac")
    if binary.exists() and os.access(str(binary), os.X_OK):
        return [str(binary)]
    if not jdk:
        on_path = shutil.which("javac")
        if on_path:
            return [on_path]
    probe = subprocess.run([java, "--list-modules"], capture_output=True, text=True)
    if probe.returncode != 0 or "jdk.compiler" not in probe.stdout:
        raise SystemExit("this java has no jdk.compiler module (%s); install a full JDK" % java)
    return [java, "-m", "jdk.compiler/com.sun.tools.javac.Main"]


def quote(path):
    path = str(path).replace("\\", "/")
    return '"%s"' % path if any(ch in path for ch in ' "') else path


def argfile(path, options, classpath, out, sources):
    lines = list(options) + ["-cp", quote(classpath), "-d", quote(out)] + [quote(s) for s in sources]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return "@%s" % path


def write_resource(manifest, out_dir):
    """Embeds the manifest the extension checks itself against: meta plus the 15 bridge tools."""
    bridge = manifest["meta"]["bridge"]["tool_names"]
    by_name = {t["name"]: t for t in manifest["tools"]}
    embedded = {"meta": manifest["meta"], "tools": [by_name[n] for n in bridge]}
    target = out_dir / "burp-tools.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(embedded, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return target


def compile_with(label, prefix, extra, api_jar, classes, sources, lint):
    """Compiles with ``--release 17``; falls back to ``-source/-target 17`` on a JDK without ct.sym."""
    classes.mkdir(parents=True, exist_ok=True)
    base = ["-encoding", "UTF-8"] + lint + extra
    args_file = BUILD / ("sources-%s.txt" % label)
    arg = argfile(args_file, base + ["--release", RELEASE], api_jar, classes, sources)
    print("compile [%s]: %d sources -> %s" % (label, len(sources), classes))
    proc = subprocess.run(prefix + [arg], capture_output=True, text=True, cwd=str(BUILD))
    output = (proc.stdout or "") + (proc.stderr or "")
    mode = "--release %s" % RELEASE
    if proc.returncode != 0 and ("release version" in output or "this.fs" in output):
        # A JDK trimmed to its runtime (Debian/Ubuntu "*-jre-headless" with jdk.compiler) has no
        # lib/ct.sym, so the compiler cannot be told which platform API to allow. -source/-target
        # keeps the language level and the class-file version, but cannot reject a newer API.
        print("  NOTE: this JDK cannot target --release %s; retrying with -source/-target %s.\n"
              "        The language level and class files stay Java %s, but the compiler no longer\n"
              "        rejects platform APIs newer than Java %s. Build once on a full JDK to get that check."
              % (RELEASE, RELEASE, RELEASE, RELEASE), file=sys.stderr)
        shutil.rmtree(str(classes))
        arg = argfile(args_file, base + ["-source", RELEASE, "-target", RELEASE, "-Xlint:-options"],
                      api_jar, classes, sources)
        proc = subprocess.run(prefix + [arg], capture_output=True, text=True, cwd=str(BUILD))
        output = (proc.stdout or "") + (proc.stderr or "")
        mode = "-source/-target %s (no platform-API check on this JDK)" % RELEASE
    if proc.returncode != 0:
        print(output)
        raise SystemExit("compilation failed [%s], exit %d" % (label, proc.returncode))
    warnings = [ln for ln in output.splitlines() if "warning" in ln]
    print("  ok [%s], %d lint warning(s)" % (mode, len(warnings)))
    return warnings, mode


def package(classes, out_jar, version):
    out_jar.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_jar.with_suffix(".jar.part")
    entries = sorted(p for p in classes.rglob("*") if p.is_file())
    manifest_text = (
        "Manifest-Version: 1.0\r\n"
        "Implementation-Title: AI Agent Bridge\r\n"
        "Implementation-Version: %s\r\n"
        "Main-Class: %s\r\n\r\n" % (version, MAIN_CLASS)
    )
    with zipfile.ZipFile(str(tmp), "w", zipfile.ZIP_DEFLATED) as jar:
        info = zipfile.ZipInfo("META-INF/MANIFEST.MF", ZIP_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        jar.writestr(info, manifest_text)
        for path in entries:
            info = zipfile.ZipInfo(path.relative_to(classes).as_posix(), ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            jar.writestr(info, path.read_bytes())
    os.replace(str(tmp), str(out_jar))

    with zipfile.ZipFile(str(out_jar)) as jar:
        bad = jar.testzip()
        versions = set()
        count = 0
        for name in jar.namelist():
            if name.endswith(".class"):
                count += 1
                head = jar.read(name)[:8]
                if head[:4] != b"\xca\xfe\xba\xbe":
                    raise SystemExit("%s is not a class file" % name)
                versions.add(struct.unpack(">H", head[6:8])[0])
        resource = "burp-tools.json" in jar.namelist()
    if bad:
        raise SystemExit("corrupt entry in %s: %s" % (out_jar, bad))
    if versions != {CLASS_MAJOR}:
        raise SystemExit("class-file versions %s in the jar, expected only {%d} (Java %s)" % (sorted(versions), CLASS_MAJOR, RELEASE))
    if not resource:
        raise SystemExit("burp-tools.json missing from the jar")
    return out_jar, count


def run_selftest(java, classpath, manifest_path, label):
    cmd = [java, "-Djava.awt.headless=true", "-cp", classpath, SELF_TEST, str(manifest_path)]
    print("\nself-test [%s]" % label)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(proc.stdout or "")
    sys.stderr.write(proc.stderr or "")
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description="Build the AI Agent Bridge extension jar.")
    ap.add_argument("--jdk", help="JDK directory to take java/javac from (default: PATH)")
    ap.add_argument("--api-jar", help="path to montoya-api-%s.jar (default: $MONTOYA_API_JAR, lib/, Maven Central)" % API_VERSION)
    ap.add_argument("--ecj-jar", help="path to ecj-%s.jar for --cross-check" % ECJ_VERSION)
    ap.add_argument("--manifest", default=str(MANIFEST),
                    help="path to the package's tools.json whose meta.bridge.tool_names lists the bridge tools "
                         "(default: %s)" % MANIFEST)
    ap.add_argument("--deps-dir", default=str(HERE / ".deps"),
                    help="where downloaded jars are stored (default: extension/.deps)")
    ap.add_argument("--check", action="store_true", help="compile only; write no jar")
    ap.add_argument("--no-lint", action="store_true", help="compile without -Xlint:all")
    ap.add_argument("--cross-check", action="store_true", help="also compile with the Eclipse compiler (ECJ)")
    ap.add_argument("--test", action="store_true", help="run the self-test after building")
    ap.add_argument("--test-java", action="append", default=[], metavar="JAVA",
                    help="also run the self-test with this java binary (repeatable)")
    args = ap.parse_args()

    manifest_path = Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = manifest["meta"]["version"]
    sources = sorted(SRC.rglob("*.java"))
    if not sources:
        raise SystemExit("no sources under %s" % SRC)
    api_jar = find_api_jar(args)
    actual = sha256_of(api_jar)
    print("Montoya API jar: %s" % api_jar)
    print("  sha256 %s%s" % (actual, "" if actual == API_SHA256 else
                            "  (NOT the pinned %s build; compiling anyway)" % API_VERSION))

    prefix = javac_prefix(args.jdk)
    lint = [] if args.no_lint else ["-Xlint:all"]
    classes = BUILD / "classes"
    if classes.exists():
        shutil.rmtree(str(classes))

    warnings, mode = compile_with("javac", prefix, [], api_jar, classes, sources, lint)
    if args.cross_check:
        ecj = find_ecj_jar(args)
        print("ECJ: %s (sha256 %s)" % (ecj, sha256_of(ecj)))
        # Same sources and classpath, second compiler: disagreements between the two are worth reading.
        compile_with("ecj", [java_binary(args.jdk), "-jar", str(ecj)], ["-warn:none"], api_jar,
                     BUILD / "classes-ecj", sources, [])
    if args.check:
        print("\ncheck passed (%s)" % mode)
        return 0

    write_resource(manifest, classes)
    out_jar, count = package(classes, BUILD / "burp-agent-bridge.jar", version)
    print("\njar: %s" % out_jar)
    print("  %d bytes, %d classes (all class-file version %d), %d lint warnings" % (
        out_jar.stat().st_size, count, CLASS_MAJOR, len(warnings)))
    print("  sha256 %s" % sha256_of(out_jar))
    for ln in warnings[:60]:
        print("  " + ln)

    if args.test:
        sep = os.pathsep
        java = java_binary(args.jdk)
        codes = [run_selftest(java, str(classes) + sep + str(api_jar), manifest_path, "classes, with the Montoya API on the classpath"),
                 run_selftest(java, str(classes), manifest_path, "classes, without the API (standalone start must not need it)")]
        for extra_java in args.test_java:
            codes.append(run_selftest(extra_java, str(classes) + sep + str(api_jar), manifest_path,
                                      "classes, %s" % extra_java))
        proc = subprocess.run([java, "-Djava.awt.headless=true", "-jar", str(out_jar), "--self-test", str(manifest_path)],
                              capture_output=True, text=True)
        print("\nself-test [java -jar, packaged jar]")
        sys.stdout.write(proc.stdout or "")
        sys.stderr.write(proc.stderr or "")
        codes.append(proc.returncode)
        if any(codes):
            print("SELF-TEST FAILED")
            return 1
        print("self-test passed in all %d modes" % len(codes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
