import unittest
from prometheus_client import CollectorRegistry, Gauge
import requests_mock
from certinator import send_pushgateway

class TestSendPushgateway(unittest.TestCase):

    def test_send_pushgateway(self):
        expiration_date_epoch = 1672564560
        job_name = 'my_certificate_metrics'
        pushgateway_address = 'localhost:9091'

        # Set up a mock response from the Pushgateway using requests_mock
        with requests_mock.Mocker() as m:
            # Mock the Pushgateway URL and response
            pushgateway_url = f'http://{pushgateway_address}/metrics/job/{job_name}'
            m.post(pushgateway_url, status_code=200)

            # Call the function being tested
            send_pushgateway(expiration_date_epoch, job_name, pushgateway_address)

            # Assertions
            # Check if the request was made correctly
            self.assertEqual(m.call_count, 1)
            self.assertEqual(m.last_request.method, 'POST')
            self.assertEqual(m.last_request.url, pushgateway_url)

            # Check if the data sent in the request is as expected
            # (You may need to adjust this based on your actual implementation)
            self.assertIn('certificate_expiration', m.last_request.text)
            self.assertIn(str(expiration_date_epoch), m.last_request.text)

if __name__ == '__main__':
    unittest.main()
