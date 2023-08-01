import argparse
import base64
import datetime
import logging
import os
import ssl
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple
from urllib.request import HTTPHandler, HTTPSHandler

import jks
import urllib3
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
from prometheus_client.exposition import _make_handler

__version__ = "0.0.1"


@dataclass
class CertificateInfo:
    """
    Represents information about a certificate.

    Attributes:
        name (str): The name or identifier of the certificate.
        path (str): The file path to the certificate.
        enabled (Optional[bool], optional): Indicates whether the certificate is enabled or disabled.
                                            Defaults to True if not specified.
        type Optional[str]: The type of the certificate, e.g., 'pem', 'pkcs12', etc.
                            If not specified, the type is guessed based on the file extension.
        password (Optional[str], optional): The password to access the certificate
                                            if it is password-protected. Defaults to None.
        alias (Optional[str], optional): The alias of the certificate in the keystore
                                         (only applicable for certain certificate types). Defaults to None.
    """
    name: str
    path: str
    enabled: Optional[bool] = True
    type: Optional[str] = None
    password: Optional[str] = None
    alias: Optional[str] = None


def setup_logger(level: int = logging.INFO):
    """Setup the root logger."""

    # disable http log output
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    urllib3.disable_warnings()

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    default_format = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(message)s")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(default_format)
    root_logger.addHandler(console_handler)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Certificate expiration exporter",
        epilog="",)
    parser.add_argument('--config',
                        '-c',
                        type=str,
                        default='config.yaml',
                        help='Path to config file')
    parser.add_argument("--verbose",
                        "-v",
                        action="store_true",
                        help="Increase output verbosity")
    parser.add_argument("--dry-run",
                        "-d",
                        action="store_true",
                        help="Do not push to Prometheus Pushgateway")
    parser.add_argument("--ignore-errors",
                        action="store_true",
                        help="Exit immediately if any error occurs")
    parser.add_argument("--version",
                        action="version",
                        version=f"certalert {__version__}")

    return parser.parse_args()


def read_config(file_path: str) -> dict:
    """Read and parse the configuration file."""

    logging.debug(f"Reading config file '{file_path}'")

    with open(file_path, 'r') as yaml_file:
        data = yaml.safe_load(yaml_file)

    return data


def check_config(config: dict) -> None:
    """Check the validity of the configuration dictionary."""

    def resolve_variable(value: str) -> str:
        """Resolve a variable from environment variables or files.
        """
        if value.startswith('env:'):
            env_var = value[4:]

            if (resolved_variable := os.environ.get(env_var)) is None:
                raise ValueError(f"Environment variable '{env_var}' not found.")

            logging.debug(f"Environment variable '{env_var}' found")
        elif value.startswith('file:'):
            file_path = value[5:]

            with open(file_path, 'r') as f:
                resolved_variable = f.read().strip()

            if resolved_variable is None:
                raise ValueError(f"Value not found in file '{file_path}'.")

            logging.debug(f"Variable in file '{file_path}' found")
        else:
            resolved_variable = value

        return resolved_variable

    logging.debug("Checking config file")

    if not (pushgateway := config.get('pushgateway')):
        raise KeyError("Key 'pushgateway' is missing.")

    if not (address := pushgateway.get('address')):
        raise KeyError("Key 'pushgateway.address' is missing.")

    # Resolve address from environment variable or file if necessary
    config['pushgateway']['address'] = resolve_variable(address)

    if (auth := pushgateway.get('auth')):
        basic, bearer = None, None
        if basic := auth.get('basic'):
            if (username := basic.get('username')) is None:
                raise KeyError("Key 'pushgateway.auth.basic.username' is missing.")
            config['pushgateway']['auth']['basic']['username'] = resolve_variable(username)

            if (password := basic.get('password')) is None:
                raise KeyError("Key 'pushgateway.auth.basic.password' is missing.")
            config['pushgateway']['auth']['basic']['password'] = resolve_variable(password)

        elif bearer := auth.get('bearer'):
            if (token := bearer.get('token')) is None:
                raise KeyError("Key 'pushgateway.auth.bearer.token' is missing.")
            config['pushgateway']['auth']['bearer']['token'] = resolve_variable(token)

        else:
            raise KeyError(f"Key 'prometheus.auth.{auth}' is an unknown type.")

        if basic and bearer:
            raise KeyError("Multiple auth types specified (prometheus.auth.basic and prometheus.auth.bearer).")

    config['pushgateway']['job'] = pushgateway.get('job', 'certalert')
    config['pushgateway']['insecure_skip_verify'] = pushgateway.get('insecure_skip_verify', False)

    if (certs := config.get('certs')) is None:
        raise KeyError("Key 'certs' is missing.")

    for cert in certs:
        cert_name = cert.get('name')
        cert_type = cert.get('type')
        cert_path = cert.get('path')

        try:
            if not cert_type:
                cert_type = guess_certificate_type(cert_path=cert_path)
                cert['type'] = cert_type
                logging.debug(f"Guessed type '{cert_type}' for certificate '{cert_name}' based on file extension.")

            if cert_type not in CERTIFICATE_TYPES.keys():
                raise TypeError(f"Type '{cert_type}' is not valid.")

            if not cert_path:
                raise AttributeError("Key 'path' is not specified.")

            if not os.path.isfile(cert_path):
                raise FileNotFoundError("Certificate not found.")

            if (password := cert.get('password')):
                cert['password'] = resolve_variable(password)
        except Exception as e:
            raise Exception(f"Invalid certificate '{cert_name}' ({cert_path}). {str(e)}")


def guess_certificate_type(cert_path: str) -> str:
    """Guess the type of a certificate based on its file extension."""

    if cert_path.endswith('.pem'):
        return 'pem'
    elif cert_path.endswith('.p12'):
        return 'pkcs12'
    elif cert_path.endswith('.jks'):
        return 'jks'
    else:
        raise TypeError(f"Unknown certificate type for file '{cert_path}'")


def extract_expiration_pem(cert: CertificateInfo) -> int:
    """Extract the expiration date of a PEM certificate from a file and return it as a Linux epoch."""

    with open(cert.path, 'rb') as pem_file:
        pem_data = pem_file.read()

    if cert.password:
        # Load the PEM data into a private key object to test the provided password
        serialization.load_pem_private_key(
            data=pem_data,
            password=cert.password.encode(),
            backend=default_backend()
        )
        logging.debug(f"Password for certificate '{cert.name}' ({cert.path}) is valid.")

    # Load the PEM data into an X.509 certificate object
    cert = x509.load_pem_x509_certificate(data=pem_data,
                                          backend=default_backend())

    epoch_time = int((cert.not_valid_after - datetime.datetime(1970, 1, 1)).total_seconds())
    return epoch_time


def extract_expiration_p12(cert: CertificateInfo) -> int:
    """Extract the expiration date of a certificate from a P12 file and return it as a Linux epoch."""

    def find_matching_certificate(p12_certificates, alias):
        """Find a certificate in a P12 file by its alias.
        """
        for c in p12_certificates[1:]:
            if isinstance(c, x509.Certificate) and c.issuer.rfc4514_string() == alias:
                return c
        return None

    with open(cert.path, 'rb') as p12_file:
        p12_data = p12_file.read()

    # Load the P12 data into a KeyStore object using the provided password
    p12 = pkcs12.load_key_and_certificates(data=p12_data,
                                           password=cert.password.encode(),
                                           backend=default_backend())

    # Validate the number of certificates in the P12 file
    num_certificates = len(p12)
    if num_certificates < 2:
        raise ValueError("No certificate found in the P12 file.")

    if num_certificates > 3 and not cert.alias:
        raise KeyError("There are more than one certificate but no alias was set.")

    if num_certificates > 3:
        logging.debug("More than one certificate found in the P12 file. Using alias as filter.")
        if (matching_certificate := find_matching_certificate(p12, cert.alias)) is None:
            raise ValueError(f"Alias '{cert.alias}' not found in the P12 file.")
        expiration_date = matching_certificate.not_valid_after
    else:
        expiration_date = p12[1].not_valid_after  # The second element is always the certificate

    epoch_time = int((expiration_date - datetime.datetime(1970, 1, 1)).total_seconds())
    return epoch_time


def extract_expiration_jks(cert: CertificateInfo) -> int:
    """Extract the expiration date of a certificate from a JKS file and return it as a Linux epoch."""

    if cert.alias is None:
        raise KeyError("Alias not specified.")

    # Load the JKS data into a KeyStore object using the provided password
    keystore = jks.KeyStore.load(filename=cert.path,
                                 store_password=cert.password)

    # Check if the provided alias exists in the KeyStore
    if not (cert_entry := keystore.entries.get(cert.alias)):
        raise ValueError(f"Alias '{cert.alias}' not found in the JKS file.")

    # iterate over certhaings in the keystore
    for c in cert_entry.cert_chain:
        logging.debug(f"Found certificate with alias '{cert.alias}' in the JKS file.")
        # load x509 certificate into cryptography object
        cert_x509 = x509.load_der_x509_certificate(data=c[2],
                                                   backend=default_backend())
        # print the expiration date
        logging.debug(f"Certificate '{cert.alias}' expires on {cert_x509.not_valid_after}")

    # Retrieve the certificate entry and extract the expiration date
    expiration_date = datetime.datetime.utcfromtimestamp(cert_entry.cert.get_not_after() / 1000)

    # Convert the expiration date to a Linux epoch and return it
    epoch_time = int((expiration_date - datetime.datetime(1970, 1, 1)).total_seconds())
    return epoch_time


# This dictionary maps the supported certificate types to their corresponding
# functions for extracting the expiration date of certificates.
CERTIFICATE_TYPES = {
    'pem': extract_expiration_pem,
    'pkcs12': extract_expiration_p12,
    'jks': extract_expiration_jks
}


def extract_certificate_expiration(cert: CertificateInfo) -> int:
    """Extract the expiration date of a certificate based on its type."""

    cert_type = cert.type
    extract_func = CERTIFICATE_TYPES.get(cert_type)
    if extract_func is None:
        raise TypeError(f"Unknown certificate type '{cert_type}'")

    return extract_func(cert)


def _make_default_handler(
        url: str,
        method: str,
        timeout: Optional[float],
        headers: List[Tuple[str, str]],
        data: bytes,
        insecure_skip_verify: bool = False,
) -> Callable[[], None]:
    """Default handler that implements HTTP/HTTPS connections."""

    handler = HTTPHandler()

    if insecure_skip_verify:
        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handler = HTTPSHandler(context=context)

    return _make_handler(url, method, timeout, headers, data, handler)


def default_handler(insecure_skip_verify: bool = False) -> Callable[[], None]:
    """Create a default handler function for HTTP/HTTPS connections."""

    def handle(url: str,
               method: str,
               timeout: Optional[float],
               headers: List[Tuple[str, str]],
               data: bytes,) -> callable:
        """Handler that implements HTTP/HTTPS connections.
        """
        return _make_default_handler(url, method, timeout, headers, data, insecure_skip_verify)

    return handle


def bearer_auth_handler(token: str,
                        insecure_skip_verify: bool = False) -> Callable[[], None]:
    """Create an authentication handler function for Bearer Token Authentication."""

    def handle(url: str,
               method: str,
               timeout: Optional[float],
               headers: List[Tuple[str, str]],
               data: bytes) -> callable:
        """Handler that implements HTTP Bearer Token Auth.
        """
        auth_value = f'{token}'.encode()
        auth_token = base64.b64encode(auth_value)
        auth_header = b'bearer ' + auth_token
        headers.append(('Authorization', auth_header))

        return _make_default_handler(url, method, timeout, headers, data, insecure_skip_verify)()

    return handle


def basic_auth_handler(username: str,
                       password: str,
                       insecure_skip_verify: bool = False) -> Callable[[], None]:
    """Create an authentication handler function for Basic Authentication."""

    def handle(url: str,
               method: str,
               timeout: Optional[float],
               headers: List[Tuple[str, str]],
               data: bytes) -> None:
        """Handler that implements HTTP Basic Auth.
        """
        auth_value = f'{username}:{password}'.encode()
        auth_token = base64.b64encode(auth_value)
        auth_header = b'Basic ' + auth_token
        headers.append(('Authorization', auth_header))

        return _make_default_handler(url, method, timeout, headers, data, insecure_skip_verify)()

    return handle


def get_pushgateway_handler(config: dict) -> Callable:
    """Get the authentication handler for the Pushgateway."""

    handler = None
    pushgateway = config.get('pushgateway')

    if (auth := pushgateway.get('auth')) is not None:
        if auth.get('basic'):
            handler = basic_auth_handler(
                username=auth.get('username'),
                password=auth.get('password'),
                insecure_skip_verify=config.get('insecure_skip_verify')
            )
        elif auth.get('bearer'):
            handler = bearer_auth_handler(token=auth.get('token'),
                                          insecure_skip_verify=config.get('insecure_skip_verify'))
        else:
            raise TypeError(f"Unknown auth type '{auth}'")

    if handler is None:
        handler = default_handler(insecure_skip_verify=config.get('insecure_skip_verify'))

    return handler


def send_pushgateway(expiration_date_epoch: int,
                     job_name: str,
                     pushgateway_url: str,
                     handler: Optional[Callable] = None) -> None:
    """Send certificate expiration metrics to the Prometheus Pushgateway."""

    registry = CollectorRegistry()

    # Create a Prometheus Gauge metric representing the certificate expiration date
    g = Gauge(name='certificate_expiration_date_epoch',
              documentation='Certificate expiration date epoch',
              registry=registry)
    g.set(expiration_date_epoch)
    g.set_to_current_time()

    logging.debug(f"Sending metrics to pushgateway '{pushgateway_url}' for job '{job_name}'")

    push_to_gateway(gateway=pushgateway_url,
                    job=job_name,
                    registry=registry,
                    handler=handler)


def process_certs(certs: List[CertificateInfo],
                  pushgateway_url: str,
                  handler: Callable,
                  job_name: str,
                  dry_run: bool = False,
                  ignore_errors: bool = False) -> None:
    """Process the certificates and send expiration metrics to the Pushgateway."""

    for cert in certs:
        try:
            cert_name = cert.get('name')
            cert_path = cert.get('path')

            if cert.get('enabled', True) is False:
                logging.info(f"Skip certificate '{cert_name}' because is disabled ({cert_path})")
                continue

            logging.info(f"Processing certificate '{cert_name}' ({cert_path})")

            expiration_date_epoch = extract_certificate_expiration(cert=CertificateInfo(**cert))
        except Exception as e:
            msg = f"Cannot extract expiration date for certificate '{cert_name}' ({cert_path}). {str(e)}"

            if ignore_errors:
                logging.warning(msg)
                continue
            raise LookupError(msg)

        # Format expiration date in human-readable format
        expiration_date = datetime.datetime.fromtimestamp(expiration_date_epoch) .strftime('%Y-%m-%d %H:%M:%S')
        logging.debug(f"Certificate '{cert_name}' ({cert_path}) expires on "
                      f"epoch {expiration_date_epoch} ({expiration_date})")

        try:
            if dry_run:
                logging.info(f"Skipping sending metrics to Pushgateway (dry run enabled)")
                continue

            send_pushgateway(expiration_date_epoch=expiration_date_epoch,
                             job_name=job_name,
                             pushgateway_url=pushgateway_url,
                             handler=handler)
        except Exception as e:
            raise ConnectionError(f"Cannot send metrics to Pushgateway: {str(e)}")


def main():
    # Parse command-line arguments
    try:
        args = parse_args()
    except Exception as e:
        sys.stderr.write(f"ERROR: Cannot parse start arguments. {str(e)}\n")
        sys.exit(1)

    level = logging.DEBUG if args.verbose else os.environ.get('LOG_LEVEL', logging.INFO)
    setup_logger(level)

    # Read and parse the configuration file
    try:
        config = read_config(file_path=args.config)
    except Exception as e:
        logging.error(f"Cannot read config file '{args.config}'. {str(e)}")
        sys.exit(1)

    # Check the validity of the configuration
    try:
        check_config(config=config)
    except Exception as e:
        logging.error(f"Invalid config file '{args.config}'. {str(e)}")
        sys.exit(1)

    # Additional config parsing
    config['pushgateway']['dry_run'] = args.dry_run
    if config['pushgateway']['dry_run']:
        logging.info("Dry run enabled. No metrics will be sent to the Pushgateway.")

    if (ignore_errors := args.ignore_errors):
        logging.warning("'--ignore-errors' is enabled, any certificate expiration evaluation "
                        "failures will be logged, but no exceptions will be raised.")

    # Send certificate expiration metrics to the Pushgateway
    try:
        handler = get_pushgateway_handler(config)
        pushgateway = config.get('pushgateway')

        process_certs(certs=config.get('certs'),
                      pushgateway_url=pushgateway.get('address'),
                      handler=handler,
                      job_name=pushgateway.get('job'),
                      dry_run=pushgateway.get('dry_run'),
                      ignore_errors=ignore_errors)

    except Exception as e:
        logging.error(f"Cannot process certificates. {str(e)}")


if __name__ == '__main__':
    main()
