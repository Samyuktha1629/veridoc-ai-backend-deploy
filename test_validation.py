import unittest

from backend.validation import _verhoeff_valid, validate_application


def _append_verhoeff_digit(prefix: str) -> str:
    for digit in "0123456789":
        if _verhoeff_valid(prefix + digit):
            return prefix + digit
    raise AssertionError("Could not generate a Verhoeff test value")


class ValidationTests(unittest.TestCase):
    def test_pan_is_masked_and_validated(self):
        result = validate_application("PAN: ABCDE1234F", "pan")
        self.assertEqual(result["fields"][0]["field"], "PAN")
        self.assertEqual(result["fields"][0]["value"], "AB******4F")
        self.assertEqual(result["invalid_fields"], [])

    def test_missing_required_pan_is_reported(self):
        result = validate_application("A short unrelated document", "pan")
        self.assertEqual(result["invalid_fields"][0]["field"], "PAN")

    def test_aadhaar_checksum_is_checked_and_masked(self):
        aadhaar = _append_verhoeff_digit("23456789012")
        result = validate_application(f"Identity number: {aadhaar}", "aadhaar")
        self.assertEqual(result["fields"][0]["field"], "Aadhaar")
        self.assertEqual(result["fields"][0]["value"], f"****{aadhaar[-4:]}")
        self.assertFalse(result["invalid_fields"])

    def test_invalid_aadhaar_checksum_is_flagged(self):
        valid = _append_verhoeff_digit("23456789012")
        replacement = str((int(valid[-1]) + 1) % 10)
        invalid = valid[:-1] + replacement
        result = validate_application(f"Identity number: {invalid}", "aadhaar")
        self.assertTrue(result["invalid_fields"])

    def test_gstin_embedded_pan_consistency_is_checked(self):
        result = validate_application("PAN ABCDE1234F GSTIN 27ABCDE1234F1Z5", "gstin")
        self.assertTrue(result["consistency_checks"][0]["passed"])
        mismatch = validate_application("PAN FGHIJ5678K GSTIN 27ABCDE1234F1Z5", "gstin")
        self.assertFalse(mismatch["consistency_checks"][0]["passed"])


if __name__ == "__main__":
    unittest.main()
