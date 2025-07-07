"""

Command-line interface for ssl_maker using Click:

Commands:
  - ca    Generate only the root CA
  - cert  Issue a leaf certificate for a given DOMAIN
  - clean Remove all generated certificates
"""

import click
import getpass
import logging
from pathlib import Path
from ssl_maker.core import CertConfig, SSLCertificateMakerEngine


@click.group()
@click.option('--verbose', is_flag=True, help='Enable debug logging')
def cli(verbose):
    """
    Top-level CLI group. Use --verbose for DEBUG output.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s %(message)s')


@cli.command()
@click.option('--ca-name', required=True, help='CA common name')
@click.option('--country', default='JP', show_default=True, help='Country code')
@click.option('--state', default='Tokyo', show_default=True, help='State or prefecture')
@click.option('--locality', default='Shibuya', show_default=True, help='City or locality')
@click.option('--organization', default='ExampleOrg', show_default=True, help='Organization name')
@click.option('--unit', default='IT', show_default=True, help='Organizational unit')
@click.option('--email', default='none@none.com', show_default=True, help='Contact email')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=False, help='Password for CA private key')
@click.option('--output-dir', default=lambda: str(Path.home() / '.ssl_maker'), show_default=True, help='Output directory')
@click.option('--force', is_flag=True, help='Overwrite existing files without prompt')
def ca(ca_name, country, state, locality, organization, unit, email, password, output_dir, force):
    """
    Generate only the root CA (self-signed).
    """
    output_dir = Path(output_dir)
    config = CertConfig(
        ca_name, country, state, locality,
        organization, unit, email,
        ca_name,  # use CA name as domain for serial purposes
        password.encode('utf-8') if isinstance(password, str) else password,
        output_dir
    )
    engine = SSLCertificateMakerEngine(config)
    if not force and any(output_dir.glob(pattern) for pattern in ('*.crt','*.key','*.pfx')):
        click.confirm(f'Certificates exist in {output_dir}. Overwrite?', abort=True)
    engine.run()
    click.echo(f'Root CA generated at {output_dir}')


@cli.command()
@click.argument('domain', nargs=1, required=True)
@click.option('--email', default='none@none.com', show_default=True, help='Contact email')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=False, help='Password to decrypt CA key')
@click.option('--output-dir', default=lambda: str(Path.home() / '.ssl_maker'), show_default=True, help='Output directory')
@click.option('--force', is_flag=True, help='Overwrite existing files without prompt')
def cert(domain, email, password, output_dir, force):
    """
    Issue a leaf certificate for DOMAIN, signed by the existing CA.
    """
    output_dir = Path(output_dir)
    config = CertConfig(
        '', '', '', '', '', '', email,
        domain,
        password.encode('utf-8') if isinstance(password, str) else password,
        output_dir
    )
    engine = SSLCertificateMakerEngine(config)
    if not force and any(output_dir.glob(f'{domain}.*')):
        click.confirm(f'Certificate for {domain} exists. Overwrite?', abort=True)
    engine.run()
    click.echo(f'Certificate for {domain} generated at {output_dir}')


@cli.command()
def clean():
    """
    Remove all generated certificates (CRT, KEY, CSR, PEM, PFX) from the default output directory.
    """
    output_dir = Path.home() / '.ssl_maker'
    for pattern in ('*.crt','*.key','*.csr','*.pem','*.pfx'):
        for file in output_dir.glob(pattern):
            file.unlink()
    click.echo(f'Cleaned all certificates in {output_dir}')


if __name__ == '__main__':
    cli()
