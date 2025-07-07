"""
Tkinter-based GUI front-end for ssl_maker.core:
Prompts user for CA and domain parameters, then invokes the engine.
"""

import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import logging

from ssl_maker.core import SSLCertificateMakerEngine, CertConfig

logger = logging.getLogger(__name__)


def confirm_overwrite(path: Path) -> bool:
    """
    If the given path exists, ask the user via a messagebox whether to overwrite.

    Args:
        path: Path of the existing certificate file to check.

    Returns:
        True if the file may be written (either doesn't exist or user confirmed).
    """
    if path.exists():
        return messagebox.askyesno(
            "Overwrite Confirmation",
            "A certificate already exists. Overwrite?\nRe-installation may be needed."
        )
    return True


def main() -> None:
    """
    Build and run the Tkinter GUI application. On 'Generate', collects inputs,
    constructs a CertConfig and SSLCertificateMakerEngine, confirms overwrite,
    and triggers certificate generation.
    """
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    root = tk.Tk()
    root.title("SSL Certificate Maker")
    root.geometry("300x350")

    labels = [
        ('CA Name', 'ca_name', 'MyCA'),
        ('Country', 'country', 'JP'),
        ('State/Prefecture', 'state', 'Tokyo'),
        ('Locality/City', 'locality', 'Shibuya'),
        ('Organization', 'organization', 'ExampleOrg'),
        ('Unit', 'unit', 'IT'),
        ('Email', 'email', 'none@none.com'),
        ('Domain', 'domain', '127.0.0.1'),
        ('Password', 'password', 'password'),
    ]
    entries: dict[str, tk.Entry] = {}
    for idx, (text, key, default) in enumerate(labels):
        tk.Label(root, text=text).grid(row=idx, column=0, sticky='w')
        entry = tk.Entry(root)
        if key == 'password':
            entry.config(show='*')
        entry.grid(row=idx, column=1)
        entry.insert(tk.END, default)
        entries[key] = entry

    def on_generate() -> None:
        """
        Callback for the 'Generate Certificates' button:
        - Read form entries
        - Build CertConfig and engine
        - Confirm overwrite of existing CA cert
        - Run generation and notify on success or error
        """
        try:
            ca_name = entries['ca_name'].get().strip()
            country = entries['country'].get().strip()
            state = entries['state'].get().strip()
            locality = entries['locality'].get().strip()
            organization = entries['organization'].get().strip()
            unit = entries['unit'].get().strip()
            email = entries['email'].get().strip()
            domain = entries['domain'].get().strip()
            password = entries['password'].get().encode('utf-8')

            output_dir = Path.home() / ".ssl_maker"
            config = CertConfig(
                ca_name=ca_name,
                country=country,
                state=state,
                locality=locality,
                organization=organization,
                unit=unit,
                email=email,
                domain=domain,
                password=password,
                output_dir=output_dir,
            )
            engine = SSLCertificateMakerEngine(config)

            ca_cert_path = output_dir / f"{engine.safe_ca_name}.crt"
            if not confirm_overwrite(ca_cert_path):
                return

            engine.run()
            messagebox.showinfo('Done', 'Certificate generation completed.')

        except Exception as e:
            logger.exception("Error during generation")
            messagebox.showerror('Error', str(e))

    tk.Button(root, text='Generate Certificates', command=on_generate).grid(
        row=len(labels), column=0, columnspan=2
    )
    root.mainloop()


if __name__ == '__main__':
    main()
