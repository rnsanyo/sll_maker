# ssl_maker

`ssl_maker` is a simple self-signed SSL/TLS certificate generator in Python.  
Supports both a command-line interface (via [Click](https://click.palletsprojects.com/)) and a minimal Tkinter GUI.

## Features

- 🔐 Create a root Certificate Authority (CA) with a 2048-bit RSA key  
- 📄 Issue leaf certificates (with SAN support for hostnames and IPs)  
- 🔑 Export keys in PEM, CRT, and PFX formats  
- 🧹 Automatic cleanup of old certificates  
- 💻 Cross-platform CLI and GUI interfaces  

## Installation

### From PyPI

```bash
pip install ssl_maker
```

> **Note**: PyPI release coming soon. Until then, install from source:

### From Source (editable)

```bash
git clone https://github.com/your-username/ssl_maker.git
cd ssl_maker
pip install -e .
```

## Usage

### Command-Line

```bash
# Generate only the root CA:
ssl-maker ca --ca-name MyRootCA

# Issue a leaf certificate for example.com:
ssl-maker cert example.com

# Remove all generated artifacts:
ssl-maker clean
```

Run `ssl-maker --help`, `ssl-maker ca --help` or `ssl-maker cert --help` for full options.

### GUI

```bash
python -m ssl_maker.gui
```

This launches a Tkinter window. Fill in your CA name, country, state, etc., click **Generate Certificates**, and find all outputs in `~/.ssl_maker/`.

## Configuration

By default, all artifacts (keys, CRTs, CSRs, PEMs, PFX) are written to:

```
~/.ssl_maker/
```

You can override this directory:

- In the **CLI** with `--output-dir /path/to/dir`
- In the **GUI** by modifying the `output_dir` assignment in `ssl_maker/gui.py`

## Development

1. Fork the repository.  
2. Clone your fork and create a branch:
   ```bash
   git clone https://github.com/rnsanyo/ssl_maker.git
   cd ssl_maker
   git checkout -b feature/my-feature
   ```
3. Install dev dependencies:
   ```bash
   pip install -e .[dev]
   ```
4. Run tests, linters, etc.  
5. Commit, push, and open a pull request.

## License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for full text.

---

### MIT License

```
MIT License

Copyright (c) 2025 Your Name

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
