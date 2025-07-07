# ssl_maker

[![PyPI version](https://img.shields.io/pypi/v/ssl_maker.svg)](https://pypi.org/project/ssl_maker/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build](https://img.shields.io/github/actions/workflow/status/rnsanyo/ssl_maker/python-package.yml)](https://github.com/rnsanyo/ssl_maker/actions)

`ssl_maker` is a Python utility that simplifies the creation of SSL/TLS certificates.
It lets you:

- 🔐 Create a root Certificate Authority (CA)
- 📄 Generate leaf certificates for domains or IPs (with SAN support)
- 🔑 Export certificates and keys in PEM, CRT, and PFX formats
- 🧹 Automatically clean up old certificates
- 💻 Use via command-line or minimal GUI (Tkinter)

## Installation

### From PyPI

```bash
pip install ssl_maker
```

### From Source (editable)

```bash
git clone https://github.com/rnsanyo/ssl_maker.git
cd ssl_maker
pip install -e .
```

## Getting Started

### CLI Example
```bash
# Generate a root CA
ssl-maker ca --ca-name MyRootCA

# Issue a cert for example.com
ssl-maker cert example.com

# Clean up everything
ssl-maker clean
```

### GUI Example
```bash
python -m ssl_maker.gui
```
This launches a Tkinter window. Fill in the form, click **Generate Certificates**, and find outputs in `~/.ssl_maker/`.

## Configuration
Artifacts are saved to:
```
~/.ssl_maker/
```
Override with:
- CLI: `--output-dir /path/to/dir`
- GUI: edit `output_dir` in `ssl_maker/gui.py`

## Development
```bash
pip install -e .[dev]
pytest
mypy .
```

## Contributing
We welcome PRs and suggestions! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE) for full text.
