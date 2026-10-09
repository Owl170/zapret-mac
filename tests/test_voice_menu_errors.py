"""A failed voice action must leave the interactive menu usable."""
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import voice_controller as v
import zapret as z


class VoiceMenuErrorTests(unittest.TestCase):
    def test_action_errors_are_reported_and_menu_can_exit(self):
        failures = (
            z.Error('voice action failed'),
            OSError('voice action failed'),
            ValueError('voice action failed'),
            subprocess.TimeoutExpired('voice action', 3),
        )
        for failure in failures:
            with self.subTest(error=type(failure).__name__):
                output = io.StringIO()
                with patch.object(z, 'require_mac'), \
                        patch.object(z, 'config', return_value=dict(z.DEFAULTS)), \
                        patch.object(v, 'show_status'), \
                        patch.object(v, 'change_voice', side_effect=failure) as change, \
                        patch('builtins.input', side_effect=['1', '', '0']), \
                        patch('sys.stdout', output):
                    v.voice_menu()
                change.assert_called_once_with(z.ROOT, enabled=True)
                self.assertIn('Ошибка:', output.getvalue())
                self.assertIn(str(failure), output.getvalue())


if __name__ == '__main__':
    unittest.main()
