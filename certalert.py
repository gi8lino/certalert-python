import argparse
import base64
import datetime
import logging
import os
import ssl
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
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
        type Optional[str]: The type of the certificate. Possible values are: 'crt', 'pem', 'pkcs12' or 'jks'.
                            If not specified, the type is guessed based on the file extension.
        password (Optional[str], optional): The password to access the certificate
                                            if it is password-protected. Defaults to None.
        position (Optional[int], optional): The position of the certificate in a PEM or PKCS12 file.
                                            If not set and the file contains multiple certificates,
                                            the first certificate in the chain is used.
        alias (Optional[str], optional): The alias of the certificate in the JKS file.
                                         Defaults to None.
        labels (Optional[Dict[str, str]], optional): Additional labels to be added to the metric.
    """
    name: str
    path: str
    enabled: Optional[bool] = True
    type: Optional[str] = None
    password: Optional[str] = None
    position: Optional[int] = None
    alias: Optional[str] = None
    labels: Optional[Dict[str, str]] = None


def setup_logger(level: int = logging.INFO):
    """Setup the root logger."""

    # disable http log output
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    urllib3.disable_warnings()

    logging.basicConfig(level=level,
                        format="%(asctime)s [%(levelname)-7.7s] %(message)s")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="certalert - Monitor SSL/TLS certificates and push alerts to Prometheus Pushgateway",
        epilog="""
certalert can extract the expiration date from the following certificate types:
- PEM (crt, pem)
- PKCS12 (p12)
- JKS (jks)

The certificate type can be specified in the config file or it can be guessed based on the file extension.
""",)
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

    config['pushgateway']['address'] = resolve_variable(address)

    if (auth := pushgateway.get('auth')):
        basic, bearer = None, None
        if (basic := auth.get('basic')):
            if (username := basic.get('username')) is None:
                raise KeyError("Key 'pushgateway.auth.basic.username' is missing.")
            config['pushgateway']['auth']['basic']['username'] = resolve_variable(username)

            if (password := basic.get('password')) is None:
                raise KeyError("Key 'pushgateway.auth.basic.password' is missing.")
            config['pushgateway']['auth']['basic']['password'] = resolve_variable(password)

        elif (bearer := auth.get('bearer')):
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

    for idx, cert in enumerate(certs):
        try:
            cert = CertificateInfo(**cert)
        except Exception as e:
            raise TypeError(f"{str(e).removeprefix('CertificateInfo.__init__() ').capitalize()}")

        try:
            if not cert.type:
                cert.type = guess_certificate_type(cert_path=cert.path)
                logging.debug(f"Guessed type '{cert.type}' for certificate '{cert.name}' based on file extension.")

            if cert.type not in CERTIFICATE_TYPES.keys():
                raise TypeError(f"Type '{cert.type}' is not valid.")

            if not cert.path:
                raise AttributeError("Key 'path' is not specified.")

            if not os.path.isfile(cert.path):
                raise FileNotFoundError(f"Certificate '{cert.path}' not found.")

            if (password := cert.password):
                cert.password = resolve_variable(password)

            if cert.position is not None:
                if cert.position < 1:
                    raise ValueError("Key 'position' must be greater one.")

                try:
                    cert.position = int(cert.position - 1)
                except Exception:
                    raise TypeError("Key 'position' must be an integer.")

            if cert.alias:
                cert.alias = str(cert.alias)  # convert to string in case it is an integer

            certs[idx] = cert  # replace the dict with the CertificateInfo object

        except Exception as e:
            if not isinstance(cert, CertificateInfo) and not cert.get('name'):
                raise Exception(f"Invalid certificate no {idx}. {str(e)}")
            raise Exception(f"Invalid certificate '{cert.name}'. {str(e)}")


def guess_certificate_type(cert_path: str) -> str:
    """Guess the type of a certificate based on its file extension."""

    if cert_path.endswith('.crt'):
        return 'crt'
    elif cert_path.endswith('.pem'):
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
    certs = x509.load_pem_x509_certificates(data=pem_data)

    if cert.position and len(certs) < cert.position:
        raise ValueError(f"Certificate position '{cert.position}' is out of range.")

    cert = certs[cert.position or 0]  # if position is not set, use the first certificate in the chain

    epoch_time = int(cert.not_valid_after.timestamp())
    return epoch_time


def extract_expiration_p12(cert: CertificateInfo) -> int:
    """Extract the expiration date of a certificate from a P12 file and return it as a Linux epoch."""

    with open(cert.path, 'rb') as p12_file:
        p12_data = p12_file.read()

    # An empty password is technically allowed in PKCS12 files
    p12_password = cert.password.encode() if cert.password is not None else None

    # Load the P12 data into a KeyStore object using the provided password
    _, cert, additional_certs = pkcs12.load_key_and_certificates(
        data=p12_data,
        password=p12_password,
        backend=default_backend()
    )

    certs = [cert] + additional_certs

    if cert.position and len(certs) < cert.position:
        raise ValueError(f"Certificate position '{cert.position}' is out of range.")

    cert = certs[cert.position or 0]  # if position is not set, use the first certificate in the chain

    epoch_time = int(cert.not_valid_after.timestamp())
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

    last_cert_in_chain = cert_entry.cert_chain[0]  # get the first certificate in the chain
    logging.debug(f"Found certificate with alias '{cert.alias}' in the JKS file.")
    # load x509 certificate into cryptography object
    cert_x509 = x509.load_der_x509_certificate(data=last_cert_in_chain[1],  # get the certificate data
                                               backend=default_backend())

    # Retrieve the certificate entry and extract the expiration date
    epoch_time = int(cert_x509.not_valid_after.timestamp())
    return epoch_time


# This dictionary maps the supported certificate types to their corresponding
# functions for extracting the expiration date of certificates.
CERTIFICATE_TYPES = {
    'pem': extract_expiration_pem,
    'crt': extract_expiration_pem,
    'pkcs12': extract_expiration_p12,
    'jks': extract_expiration_jks
}


def extract_certificate_expiration(cert: CertificateInfo) -> int:
    """Extract the expiration date of a certificate based on its type."""

    cert.type = cert.type
    extract_func = CERTIFICATE_TYPES.get(cert.type)
    if extract_func is None:
        raise TypeError(f"Unknown certificate type '{cert.type}'")

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


def send_pushgateway(instance: str,
                     expiration_date_epoch: int,
                     job_name: str,
                     pushgateway_url: str,
                     labels: Optional[Dict[str, str]] = None,
                     handler: Optional[Callable] = None) -> None:
    """Send certificate expiration metrics to the Prometheus Pushgateway."""

    if labels is None:
        labels = {}

    # Pushgateway does not allow spaces in labels
    instance = instance.replace(' ', '_')
    labels = {k.replace(' ', '_'): v.replace(' ', '_') for k, v in labels.items()}
    labels.update({'instance': instance})  # merge instance name into additional labels

    registry = CollectorRegistry()

    # Create a Prometheus Gauge metric representing the certificate expiration date
    g = Gauge(name='certificate_expiration_date_epoch',
              documentation='Certificate expiration date epoch',
              registry=registry)
    g.set(expiration_date_epoch)
    g.set_to_current_time()

    logging.debug(f"Sending metrics to pushgateway '{pushgateway_url}' "
                  f"for job '{job_name}' with instance '{instance}'")

    push_to_gateway(gateway=pushgateway_url,
                    job=job_name,
                    registry=registry,
                    grouping_key=labels,
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
            if not cert.enabled:
                logging.info(f"Skip certificate '{cert.name}' because is disabled ({cert.path})")
                continue

            logging.info(f"Processing certificate '{cert.name}' ({cert.path})")

            expiration_date_epoch = extract_certificate_expiration(cert=cert)
        except Exception as e:
            msg = f"Cannot extract expiration date for certificate '{cert.name}' ({cert.path}). {str(e)}"

            if ignore_errors:
                logging.warning(msg)
                continue
            raise LookupError(msg)

        # Format expiration date in human-readable format
        expiration_date = datetime.datetime.fromtimestamp(expiration_date_epoch) .strftime('%Y-%m-%d %H:%M:%S')
        logging.debug(f"Certificate '{cert.name}' ({cert.path}) expires on "
                      f"epoch {expiration_date_epoch} ({expiration_date})")

        try:
            if dry_run:
                logging.info(f"Skipping sending metrics to Pushgateway (dry run enabled)")
                continue

            send_pushgateway(instance=cert.name,
                             expiration_date_epoch=expiration_date_epoch,
                             job_name=job_name,
                             pushgateway_url=pushgateway_url,
                             labels=cert.labels,
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

    # Setup logging
    setup_logger(logging.DEBUG if args.verbose else logging.INFO)

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
