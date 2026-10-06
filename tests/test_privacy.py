"""验证不可逆身份映射与最小披露化名。"""

import unittest

from science_strategy_foundation.privacy import (
    generate_pepper,
    research_pseudonym,
    subject_code_hash,
)


class PrivacyTest(unittest.TestCase):
    def test_local_code_maps_irreversibly_and_deterministically(self):
        pepper = generate_pepper()
        first = subject_code_hash(pepper, "siteA", "A-001")
        second = subject_code_hash(pepper, "siteA", "A-001")
        other_site = subject_code_hash(pepper, "siteB", "A-001")
        other_code = subject_code_hash(pepper, "siteA", "A-002")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other_site)
        self.assertNotEqual(first, other_code)
        # 摘要是定长十六进制，且不包含原始编号。
        self.assertEqual(64, len(first))
        self.assertNotIn("A-001", first)

    def test_different_pepper_breaks_correlation(self):
        h1 = subject_code_hash(generate_pepper(), "siteA", "A-001")
        h2 = subject_code_hash(generate_pepper(), "siteA", "A-001")
        self.assertNotEqual(h1, h2)

    def test_pseudonym_is_isolated_per_application(self):
        pepper = generate_pepper()
        one = research_pseudonym(pepper, "app1", "participant-1")
        same_app = research_pseudonym(pepper, "app1", "participant-1")
        other_app = research_pseudonym(pepper, "app2", "participant-1")
        other_participant = research_pseudonym(pepper, "app1", "participant-2")
        self.assertEqual(one, same_app)
        self.assertNotEqual(one, other_app)
        self.assertNotEqual(one, other_participant)
        self.assertNotIn("participant-1", one)


if __name__ == "__main__":
    unittest.main()
