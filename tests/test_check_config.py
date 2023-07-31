import unittest
from unittest.mock import patch, mock_open
import os
import tempfile
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))


from certalert import check_config

class TestCheckConfig(unittest.TestCase):

    def setUp(self):
        self.config = {
            'pushgateway': {
                'address': 'env:PROMETHEUS_ADDRESS',
                'auth': {
                    'basic': {
                        'username': 'user',
                        'password': 'env:BASIC_PASSWORD',
                    },
                },
                'job': 'certinator',
                'insecure_skip_verify': False,
            },
            'certs': [
                {
                    'name': 'Cert1',
                    'type': 'pem',
                    'path': 'file:tests/certs/p12/certificate.p12',
                    'password': 'env:PASSWORD1',
                },
                {
                    'name': 'Cert2',
                    'enabled': 'false',
                    'path': 'file:/path/to/cert2.pem',
                },
            ],
        }

    @patch.dict(os.environ, {
        'PROMETHEUS_ADDRESS': 'http://example.com',
        'BASIC_PASSWORD': 'secret',
        'PASSWORD1': 'password1',
    })
    @patch('builtins.open', mock_open(read_data=''))
    @patch('os.path.isfile')
    def test_valid_config(self, mock_isfile):
        try:
            mock_isfile.return_value = True
            check_config(self.config)
        except Exception as e:
            self.fail(f"Unexpected exception: {e}")


if __name__ == '__main__':
    unittest.main()
