# /// script
# requires-python = ">=3.12"
# ///
import importlib.util
import json
from unittest import mock
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b = module('build-public-engine')
COMMIT = '254b59607d4417e9dffbc307138ae5c86280fe4c'
# Fixture roots under the filesystem root, so the same names are absolute on every OS.
BASE = os.path.abspath(os.sep)


def missing(path):
    raise FileNotFoundError(path)


class Remap(unittest.TestCase):
    def test_every_builder_root_maps_to_a_logical_prefix_most_specific_last(self):
        engine, cargo_home = os.path.join(BASE, 'b', 'omd = engine'), os.path.join(BASE, 'c', 'cargo home')
        target, sysroot = os.path.join(engine, 'target'), os.path.join(BASE, 'h', 'user', '.rustup', 'toolchains', '1.93.0')
        alias = os.path.join(BASE, 'private', 'b', 'omd = engine')
        def realpath(host):
            if host == engine:
                return alias
            if host.endswith(os.path.join('src', 'rust')):
                missing(host)
            return host
        entries = b.public_paths(engine, target, cargo_home, {'sysroot': sysroot, 'commit': COMMIT}, realpath=realpath)
        self.assertEqual([(e['role'], e['host'], e['logical'], e['alias']) for e in entries], [
            ('cargo-home', cargo_home, '/cargo', False),
            ('engine', engine, '/omd/engine', False),
            ('target', target, '/omd/target', False),
            ('engine', alias, '/omd/engine', True),
            ('toolchain', sysroot, '/rust/toolchain', False),
            ('rust-src', os.path.join(sysroot, 'lib', 'rustlib', 'src', 'rust'), f'/rustc/{COMMIT}', False),
        ])
        args = b.encode(entries).split('\x1f')
        self.assertEqual(len(args), len(entries))
        for arg, entry in zip(args, entries):
            # rustc splits at the last '=', so hosts may contain '=' and spaces stay inside one argument.
            host, _, logical = arg.removeprefix('--remap-path-prefix=').rpartition('=')
            self.assertEqual((host, logical), (entry['host'], entry['logical']))
        generated = os.path.join(target, 'release', 'build', 'x', 'out', 'gen.rs')
        self.assertEqual([e for e in entries if generated.startswith(e['host'] + os.sep)][-1]['role'], 'target')

    def test_ambiguous_relative_or_unencodable_roots_are_refused(self):
        same, c = (lambda host: host), os.path.join(BASE, 'c')
        path = os.path.join(BASE, 'same')
        with self.assertRaisesRegex(ValueError, 'cannot be both engine and target'):
            b.remap([{'role': 'engine', 'host': path, 'logical': '/omd/engine'}, {'role': 'target', 'host': path, 'logical': '/omd/target'}], realpath=same)
        self.assertEqual(len(b.remap([{'role': 'a', 'host': path + os.sep, 'logical': '/x'}, {'role': 'b', 'host': path, 'logical': '/x'}], realpath=same)), 1)
        for root, message in [({'role': 'target', 'host': os.path.join('relative', 'target'), 'logical': '/omd/target'}, 'target path must be absolute'),
                              ({'role': 'cargo-home', 'host': os.path.join(c, 'a\x1fb'), 'logical': '/cargo'}, 'control character'),
                              ({'role': 'cargo-home', 'host': c, 'logical': '/cargo=x'}, 'Invalid logical prefix'),
                              ({'role': 'cargo-home', 'host': c, 'logical': 'relative'}, 'Invalid logical prefix')]:
            with self.assertRaisesRegex(ValueError, message):
                b.remap([root], realpath=same)

    def test_override_names_and_cargo_configuration_are_classified_exactly(self):
        env = dict.fromkeys(['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS', 'CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS', 'CARGO_PROFILE_RELEASE_RUSTFLAGS',
                             'RUSTC', 'CARGO_BUILD_RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
                             'CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_STRIP', 'CARGO_TARGET_DIR', 'CARGO_HOME', 'RUSTUP_TOOLCHAIN', 'RUSTDOCFLAGS',
                             'CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER'], '')
        self.assertEqual(b.overrides(env), sorted(['CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTFLAGS',
                                                   'CARGO_ENCODED_RUSTFLAGS', 'CARGO_PROFILE_RELEASE_RUSTFLAGS', 'CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS',
                                                   'RUSTC', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_WRAPPER', 'RUSTFLAGS']))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            start, home = root / 'a/b', root / 'home'
            (start / '.cargo').mkdir(parents=True)
            (root / 'a/.cargo').mkdir()
            home.mkdir()
            for text, blocked in [('[target.aarch64-apple-darwin]\nlinker = "cc"\n', False), ('[build]\nrustflags = ["-Cdebuginfo=2"]\n', True),
                                  ('build.rustc-workspace-wrapper = "x"\n', True), ('[target.\'cfg(unix)\']\n"rustflags" = []\n', True),
                                  ('[build]\nrustc = "/opt/rustc"\n', True), ('[build]\nrustdocflags = []\njobs = 4\n', False)]:
                (start / '.cargo/config.toml').write_text(text)
                self.assertEqual(b.cargo_configs(start, home), [{'file': str(start / '.cargo/config.toml'), 'overrides': blocked}], text)
            (root / 'a/.cargo/config').write_text('[build]\nrustflags = []\n')
            (home / 'config.toml').write_text('[net]\noffline = true\n')
            self.assertEqual([(c['file'], c['overrides']) for c in b.cargo_configs(start, home)],
                             [(str(start / '.cargo/config.toml'), False), (str(root / 'a/.cargo/config'), True), (str(home / 'config.toml'), False)])

    def test_post_build_scan_reports_exact_builder_roots_and_the_home_directory(self):
        entries = [{'role': 'cargo-home', 'host': '/c/cargo home', 'logical': '/cargo'}, {'role': 'engine', 'host': '/b/engine', 'logical': '/omd/engine'}]
        data = b'x/c/cargo home/registry/a.rs\0/cargo/registry/b.rs\0/c/cargo home/registry/c.rs\0/omd/engine/crates/x.rs\0/Users/someone/.rustup/x'
        self.assertEqual(b.leaks(data, entries, '/Users/other'), [{'host': '/c/cargo home', 'count': 2}])
        self.assertEqual(b.leaks(data, entries, '/Users/someone'), [{'host': '/c/cargo home', 'count': 2}, {'host': '/Users/someone', 'count': 1}])
        self.assertEqual(b.leaks(b'/cargo/registry/b.rs /omd/engine/crates/x.rs', entries, '/Users/someone'), [])


class Entry(unittest.TestCase):
    """The command-line entry, run from a copy of the script in a scratch engine root."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve() / 'engine root'
        (self.root / 'scripts').mkdir(parents=True)
        shutil.copy2(Path(__file__).with_name('build-public-engine.py'), self.root / 'scripts')
        (self.root / 'cargo home').mkdir()
        self.env = {k: v for k, v in os.environ.items() if not b.OVERRIDES.fullmatch(k) and k not in ('CARGO_TARGET_DIR', 'CARGO_HOME')}
        self.env['CARGO_HOME'] = str(self.root / 'cargo home')

    def run_entry(self, *args, **env):
        return subprocess.run([sys.executable, '-I', str(self.root / 'scripts/build-public-engine.py'), *args], cwd=self.root,
                              env={**self.env, **env}, capture_output=True, text=True)

    def test_check_reports_the_plan_and_refuses_overrides_without_building(self):
        result = self.run_entry('--target', 'aarch64-apple-darwin', '--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = __import__('json').loads(result.stdout)
        self.assertEqual(report['status'], 'checked')
        self.assertFalse(report['release_accepted'])
        roles = {e['role']: e['logical'] for e in report['remap'] if not e['alias']}
        self.assertEqual(roles, {'engine': '/omd/engine', 'target': '/omd/target', 'cargo-home': '/cargo', 'toolchain': '/rust/toolchain', 'rust-src': roles['rust-src']})
        self.assertRegex(roles['rust-src'], r'^/rustc/[0-9a-f]{40}$')
        self.assertEqual({e['host'] for e in report['remap'] if e['role'] in ('engine', 'target', 'cargo-home') and not e['alias']},
                         {str(self.root), str(self.root / 'target'), str(self.root / 'cargo home')})
        self.assertFalse((self.root / 'target').exists())
        for name, value in [('RUSTFLAGS', '-Cdebuginfo=2'), ('CARGO_ENCODED_RUSTFLAGS', ''), ('RUSTC_WORKSPACE_WRAPPER', 'x'), ('CARGO_BUILD_RUSTC', '/opt/rustc')]:
            result = self.run_entry('--target', 'aarch64-apple-darwin', '--check', **{name: value})
            self.assertEqual(result.returncode, 2, name)
            self.assertIn(f'sets its own Rust path remapping; unset {name}', result.stderr)
        (self.root / '.cargo').mkdir()
        (self.root / '.cargo/config.toml').write_text('[build]\nrustflags = ["-Cdebuginfo=2"]\n')
        result = self.run_entry('--target', 'aarch64-apple-darwin', '--check')
        self.assertEqual(result.returncode, 2)
        self.assertIn('Cargo configuration would replace or bypass the public path remapping', result.stderr)

    def test_build_needs_a_new_absolute_output_and_a_supported_target(self):
        for args, message in [(['--target', 'aarch64-apple-darwin'], 'new absolute directory'),
                              (['--target', 'aarch64-apple-darwin', '--output', 'relative'], 'new absolute directory'),
                              (['--target', 'aarch64-apple-darwin', '--output', str(self.root)], 'new absolute directory'),
                              (['--target', 'wasm32-wasip1', '--check'], 'Unsupported public engine target')]:
            result = self.run_entry(*args)
            self.assertEqual(result.returncode, 2, args)
            self.assertIn(message, result.stderr)


@unittest.skipUnless(sys.platform == 'darwin', 'public builds run on macOS')
class LiveRustc(unittest.TestCase):
    """Like Cargo's release profile the probe strips debuginfo: an unstripped macOS link
    keeps the linker's debug map of prebuilt standard-library objects."""

    def test_remapped_output_keeps_no_builder_path_for_a_root_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='omd remap probe = ') as tmp:
            root = Path(tmp)
            (root / 'src').mkdir()
            (root / 'src/dep.rs').write_text('use std::collections::BTreeMap;\n#[inline(never)]\npub fn pick<T: Clone + Ord>(v: &[T], i: usize) -> T { let mut m = BTreeMap::new(); '
                                             'for (k, x) in v.iter().enumerate() { m.insert(x.clone(), k); } let _ = m.len(); v[i].clone() }\n'
                                             'pub fn chan() -> u8 { let (s, r) = std::sync::mpsc::channel::<u8>(); s.send(1).unwrap(); r.recv().unwrap() }\n')
            (root / 'src/main.rs').write_text('fn main() { let a: Vec<String> = std::env::args().collect(); println!("{} {}", dep::pick(&a, a.len() + 1), dep::chan()); }\n')
            tool = b.toolchain(root, dict(os.environ))
            entries = b.public_paths(root, root / 'target', root / 'cargo home', tool)

            def build(name, flags):
                out = root / 'target' / name
                out.mkdir(parents=True)
                for args in (['--crate-type', 'rlib', '--crate-name', 'dep', str(root / 'src/dep.rs'), '--out-dir', str(out)],
                             [str(root / 'src/main.rs'), '--extern', f'dep={out / "libdep.rlib"}', '-o', str(out / 'probe')]):
                    result = subprocess.run(['rustc', '--edition', '2021', '-O', '-C', 'strip=debuginfo', *args, *flags], cwd=root, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                return (out / 'probe').read_bytes()

            plain, remapped = build('plain', []), build('remapped', b.encode(entries).split('\x1f'))
            self.assertIn(str(root / 'src/dep.rs').encode(), plain, 'control: unmapped output embeds the builder root')
            self.assertEqual(b.leaks(remapped, entries), [])
            self.assertIn(b'/omd/engine/src/dep.rs', remapped)
            rust_src = Path(tool['sysroot'], 'lib/rustlib/src/rust')
            if rust_src.exists():
                # With rust-src installed, rustc embeds its local copy for generic library code.
                self.assertIn(str(rust_src).encode(), plain, 'control: unmapped output embeds the local rust-src path')
                self.assertIn(f'/rustc/{tool["commit"]}/library/'.encode(), remapped)


class ReviewRegressions(unittest.TestCase):
    def test_escaped_keys_are_semantic_and_comments_are_not_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / '.cargo').mkdir(); home = root / 'home'; home.mkdir()
            for key in ('rustc', 'rustflags', 'rustc-wrapper', 'rustc-workspace-wrapper'):
                encoded = '"' + ''.join(chr(92) + 'u' + format(ord(c), '04x') for c in key) + '"'
                (root / '.cargo/config.toml').write_text('[build]\n' + encoded + ' = "unused"\n')
                self.assertTrue(b.cargo_configs(root, home)[0]['overrides'])
            (root / '.cargo/config.toml').write_text('# rustc = "example"\n[env]\nNOTE = "rustflags = example"\n')
            self.assertFalse(b.cargo_configs(root, home)[0]['overrides'])
            (root / '.cargo/config.toml').write_text('[broken')
            with self.assertRaisesRegex(ValueError, 'Cannot parse Cargo configuration'):
                b.cargo_configs(root, home)

    @unittest.skipUnless(shutil.which('cargo'), 'requires Cargo metadata')
    def test_explicit_target_overrides_config_and_relative_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); (root / '.cargo').mkdir(); (root / 'src').mkdir()
            (root / 'Cargo.toml').write_text('[package]\nname="target-probe"\nversion="0.1.0"\nedition="2021"\n')
            (root / 'src/main.rs').write_text('fn main() {}')
            (root / '.cargo/config.toml').write_text('[build]\ntarget-dir="alternate-target"\n')
            env = {**os.environ, 'CARGO_HOME': str(root / 'home')}
            for key in list(env):
                if b.OVERRIDES.fullmatch(key) or key == 'CARGO_TARGET_DIR': env.pop(key)
            def metadata(e):
                p = subprocess.run(['cargo', 'metadata', '--offline', '--no-deps', '--format-version', '1'], cwd=root, env=e, capture_output=True, text=True, check=True)
                return json.loads(p.stdout)['target_directory']
            self.assertEqual(metadata(env), str(root / 'alternate-target'))
            with mock.patch.object(b, 'toolchain', return_value={'sysroot': str(root / 'rust'), 'commit': COMMIT, 'verbose': 'fixture'}):
                for target in (None, '../relative target'):
                    current = {**env, **({'CARGO_TARGET_DIR': target} if target else {})}
                    plan = b.plan('aarch64-apple-darwin', current, root=root)
                    at = plan['command'].index('--target-dir')
                    self.assertEqual(plan['command'][at + 1], plan['target_dir'])
                    self.assertEqual(metadata({**current, 'CARGO_HOME': plan['cargo_home'], 'CARGO_TARGET_DIR': plan['target_dir']}), plan['target_dir'])


if __name__ == '__main__':
    unittest.main()
