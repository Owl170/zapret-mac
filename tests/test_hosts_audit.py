"""Malformed ownership markers must not cause another hosts block to be added."""
import unittest
import zapret as z


class HostsAuditTests(unittest.TestCase):
    def test_inline_marker_is_rejected_instead_of_silently_kept(self):
        for text in [
            '127.0.0.1 localhost\n# old comment ' + z.HOST_BEGIN + '\n' + z.HOST_END + '\n',
            z.HOST_BEGIN + '\n1.2.3.4 example.com\n' + z.HOST_END + ' trailing text\n',
        ]:
            with self.subTest(text=text):
                with self.assertRaisesRegex(z.Error, 'отдельных строках'):
                    z.strip_hosts_block(text)

    def test_valid_end_marker_without_final_newline_removes_only_owned_block(self):
        original = '127.0.0.1 localhost\n# user comment\n'
        block = z.HOST_BEGIN + '\n1.2.3.4 example.com\n' + z.HOST_END
        self.assertEqual(z.strip_hosts_block(original + block), original)


if __name__ == '__main__':
    unittest.main()
