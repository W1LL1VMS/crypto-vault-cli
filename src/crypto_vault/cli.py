import argparse
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text

from crypto_vault import crypto

console = Console()


def print_banner():
    """Affiche la bannière d'accueil de l'outil."""
    banner_text = Text("🔐 CRYPTO VAULT CLI", style="bold cyan", justify="center")
    subtitle = Text("Chiffrement hybride AES-256 + RSA-2048", style="dim", justify="center")
    console.print(Panel.fit(
        f"{banner_text}\n{subtitle}",
        border_style="cyan",
        padding=(1, 4)
    ))


def print_success(message: str):
    console.print(f"[bold green]✔ SUCCÈS[/bold green]  {message}")


def print_error(message: str):
    console.print(f"[bold red]✘ ERREUR[/bold red]  {message}")


def print_info(message: str):
    console.print(f"[bold blue]ℹ INFO[/bold blue]  {message}")


def with_progress(task_description: str, func, *args, **kwargs):
    """Exécute une fonction en affichant une barre de progression stylée."""
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="green"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(task_description, total=100)
        # Simulation de progression pendant l'exécution réelle
        result = func(*args, **kwargs)
        progress.update(task, completed=100)
    return result


def cmd_generate_keys(args):
    """Commande : génération d'une paire de clés RSA."""
    print_info(f"Génération d'une paire de clés RSA-{args.key_size} bits...")

    keys_dir = Path(args.output_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)

    private_path = keys_dir / "private_key.pem"
    public_path = keys_dir / "public_key.pem"

    if private_path.exists() or public_path.exists():
        console.print(f"[bold yellow]⚠ Attention[/bold yellow] des clés existent déjà dans {keys_dir}")
        confirm = console.input("Écraser ? [y/N] : ")
        if confirm.lower() != "y":
            print_info("Génération annulée.")
            return

    def _generate():
        private_key, public_key = crypto.generate_rsa_keypair(args.key_size)
        crypto.save_private_key(private_key, str(private_path))
        crypto.save_public_key(public_key, str(public_path))

    with_progress("Génération des clés...", _generate)

    table = Table(title="Clés générées", border_style="green")
    table.add_column("Type", style="cyan")
    table.add_column("Emplacement", style="white")
    table.add_row("Clé privée", str(private_path))
    table.add_row("Clé publique", str(public_path))
    console.print(table)

    print_success("Paire de clés générée avec succès.")
    console.print("[bold yellow]⚠ Ne partage JAMAIS ta clé privée.[/bold yellow]")


def cmd_encrypt(args):
    """Commande : chiffrement d'un fichier."""
    input_path = Path(args.input)
    if not input_path.exists():
        print_error(f"Le fichier '{input_path}' n'existe pas.")
        sys.exit(1)

    public_key_path = Path(args.public_key)
    if not public_key_path.exists():
        print_error(f"Clé publique introuvable : '{public_key_path}'")
        sys.exit(1)

    output_path = Path(args.output) if args.output else input_path.with_suffix(input_path.suffix + ".enc")

    print_info(f"Chiffrement de '{input_path.name}'...")

    def _encrypt():
        public_key = crypto.load_public_key(str(public_key_path))
        crypto.encrypt_file(str(input_path), str(output_path), public_key)

    with_progress("Chiffrement en cours...", _encrypt)

    original_size = input_path.stat().st_size
    encrypted_size = output_path.stat().st_size

    table = Table(title="Résumé du chiffrement", border_style="green")
    table.add_column("Champ", style="cyan")
    table.add_column("Valeur", style="white")
    table.add_row("Fichier source", str(input_path))
    table.add_row("Fichier chiffré", str(output_path))
    table.add_row("Taille originale", f"{original_size} octets")
    table.add_row("Taille chiffrée", f"{encrypted_size} octets")
    console.print(table)

    print_success(f"Fichier chiffré : {output_path}")


def cmd_decrypt(args):
    """Commande : déchiffrement d'un fichier."""
    input_path = Path(args.input)
    if not input_path.exists():
        print_error(f"Le fichier '{input_path}' n'existe pas.")
        sys.exit(1)

    private_key_path = Path(args.private_key)
    if not private_key_path.exists():
        print_error(f"Clé privée introuvable : '{private_key_path}'")
        sys.exit(1)

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_suffix("") if input_path.suffix == ".enc" else Path(str(input_path) + ".dec")

    print_info(f"Déchiffrement de '{input_path.name}'...")

    def _decrypt():
        private_key = crypto.load_private_key(str(private_key_path))
        crypto.decrypt_file(str(input_path), str(output_path), private_key)

    try:
        with_progress("Déchiffrement en cours...", _decrypt)
    except ValueError:
        print_error("Échec du déchiffrement : clé incorrecte ou fichier corrompu.")
        sys.exit(1)

    print_success(f"Fichier déchiffré : {output_path}")


def build_parser():
    """Construit le parseur d'arguments avec ses sous-commandes."""
    parser = argparse.ArgumentParser(
        prog="crypto-vault",
        description="Outil de chiffrement hybride AES-256 + RSA-2048"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_keys = subparsers.add_parser("generate-keys", help="Générer une paire de clés RSA")
    p_keys.add_argument("--output-dir", default="keys", help="Dossier de sortie (défaut: keys/)")
    p_keys.add_argument("--key-size", type=int, default=2048, help="Taille de la clé RSA en bits (défaut: 2048)")
    p_keys.set_defaults(func=cmd_generate_keys)

    p_enc = subparsers.add_parser("encrypt", help="Chiffrer un fichier")
    p_enc.add_argument("input", help="Chemin du fichier à chiffrer")
    p_enc.add_argument("--public-key", default="keys/public_key.pem", help="Chemin de la clé publique")
    p_enc.add_argument("--output", help="Chemin du fichier de sortie (défaut: <fichier>.enc)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = subparsers.add_parser("decrypt", help="Déchiffrer un fichier")
    p_dec.add_argument("input", help="Chemin du fichier .enc à déchiffrer")
    p_dec.add_argument("--private-key", default="keys/private_key.pem", help="Chemin de la clé privée")
    p_dec.add_argument("--output", help="Chemin du fichier de sortie")
    p_dec.set_defaults(func=cmd_decrypt)

    return parser


def run():
    """Point d'entrée principal de la CLI."""
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except Exception as e:
        print_error(f"Une erreur inattendue est survenue : {e}")
        sys.exit(1)