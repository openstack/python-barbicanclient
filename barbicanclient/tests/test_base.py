import testtools

from barbicanclient import base


class TestValidateRef(testtools.TestCase):

    def test_valid_ref(self):
        ref = 'http://localhost/ff2ca003-5ebb-4b61-8a17-3f9c54ef6356'
        self.assertTrue(base.validate_ref(ref, 'Thing'))

    def test_invalid_uuid(self):
        ref = 'http://localhost/not_a_uuid'
        self.assertRaises(ValueError, base.validate_ref, ref, 'Thing')
