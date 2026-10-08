"""The executable controller and imported voice backend share one Error class."""
from pathlib import Path
import subprocess
import sys
import unittest


class CliModuleIdentityTests(unittest.TestCase):
    def test_voice_module_errors_use_the_cli_error_handler(self):
        root = Path(__file__).resolve().parents[1]
        # A fresh process reproduces how `python zapret.py` imports the backend.
        # Only the macOS guard and backend operation are replaced: neither PF,
        # installed files nor platform-dependent modules are touched.
        script = r'''
import importlib.abc
import importlib.util
from pathlib import Path
import runpy
import sys
import types

class VoiceShim(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'voice_controller':
            return importlib.util.spec_from_loader(fullname, self)
    def create_module(self, spec):
        return types.ModuleType(spec.name)
    def exec_module(self, module):
        import zapret as controller
        def fail(*args, **kwargs):
            raise controller.Error('injected voice failure')
        module.voice_menu = module.show_status = module.observe = fail

def guard(frame, event, arg):
    if event == 'call' and frame.f_code.co_name == 'main' and Path(frame.f_code.co_filename).name == 'zapret.py':
        frame.f_globals['require_mac'] = lambda *args, **kwargs: None
        sys.settrace(None)
    return guard

source = str(Path('zapret.py').resolve())
command = sys.argv[1]
sys.argv = [source, command]
sys.meta_path.insert(0, VoiceShim())
sys.settrace(guard)
runpy.run_path(source, run_name='__main__')
'''
        for command in ('voice-status', 'voice-menu'):
            with self.subTest(command=command):
                result = subprocess.run([sys.executable, '-X', 'utf8', '-c', script, command],
                                        cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=15)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('Ошибка: injected voice failure', result.stderr)
                self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
