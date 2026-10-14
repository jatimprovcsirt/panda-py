"""
CLI commands for PANDA SDK.

Provides initialization, key generation, status, and other CLI operations.
"""

import os
import sys
import json
import base64
import secrets
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict, fields

import click

# Read rather than repeated. This said "0.1.0" while pyproject.toml said
# 0.2.0, so `panda --version` reported a version that had never been
# released — a fourth place the number lived, disagreeing with the other
# three.
from .. import __version__

from ..crypto import (
    LocalKeyProvider,
    VaultKeyProvider,
    InfisicalKeyProvider,
    InvalidTokenError,
    validate_token,
    validate_token_format,
    is_demo_token,
    is_local_environment,
)


# Panda directory structure
PANDA_DIR_NAME = ".panda"
CREDENTIALS_FILE = "credentials"
CONFIG_FILE = "config.json"
KEYS_FILE = "keys.json"


@dataclass
class PandaCredentials:
    """Stored credentials for PANDA."""
    token: Optional[str] = None
    provider: str = "local"
    default_kid: Optional[str] = None
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    vault_role_id: Optional[str] = None
    vault_secret_id: Optional[str] = None
    vault_auth_method: Optional[str] = None  # "approle" or "token"
    vault_mount: Optional[str] = None
    vault_token_ttl: Optional[int] = None  # Token TTL in seconds (default: 3600)
    infisical_site_url: Optional[str] = None
    infisical_client_id: Optional[str] = None
    infisical_client_secret: Optional[str] = None
    infisical_project_id: Optional[str] = None
    infisical_environment: Optional[str] = None
    infisical_cache_ttl: Optional[int] = None
    keys: dict = None

    def __post_init__(self):
        if self.keys is None:
            self.keys = {}


def get_panda_dir() -> Path:
    """Get the .panda directory path."""
    return Path.cwd() / PANDA_DIR_NAME


def credentials_exist() -> bool:
    """Check if PANDA credentials exist."""
    panda_dir = get_panda_dir()
    return panda_dir.exists() and (panda_dir / CREDENTIALS_FILE).exists()


def read_credentials() -> Optional[PandaCredentials]:
    """Read stored credentials."""
    panda_dir = get_panda_dir()
    creds_file = panda_dir / CREDENTIALS_FILE

    if not creds_file.exists():
        return None

    try:
        with open(creds_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    # Unknown keys are dropped rather than raised on. A file written by a
    # newer CLI carries fields this version does not know about, and passing
    # them to the constructor raises TypeError — which the handler here used
    # to swallow along with genuinely corrupt JSON, returning None. The
    # effect was that a perfectly readable credentials file looked missing,
    # so `panda status` reported an uninitialised project and the only clue
    # was silence.
    known = {f.name for f in fields(PandaCredentials)}
    return PandaCredentials(**{k: v for k, v in data.items() if k in known})


def write_credentials(credentials: PandaCredentials) -> None:
    """Write credentials to storage."""
    panda_dir = get_panda_dir()
    panda_dir.mkdir(parents=True, exist_ok=True)

    creds_file = panda_dir / CREDENTIALS_FILE
    with open(creds_file, "w", encoding="utf-8") as f:
        json.dump(asdict(credentials), f, indent=2, default=str)

    # Set restrictive permissions on Unix-like systems
    try:
        import stat
        os.chmod(creds_file, stat.S_IRUSR | stat.S_IWUSR)
    except (AttributeError, OSError):
        pass


@click.group()
@click.version_option(version=__version__)
def cli():
    """PANDA - Private And Secure Data Access SDK."""
    pass


@cli.command()
@click.option("--token", help="PANDA access token")
@click.option(
    "--kid",
    default="default-key",
    show_default=True,
    help="Key Identifier (quick mode)",
)
@click.option(
    "--quick",
    is_flag=True,
    help="Skip wizard, use quick setup with local provider",
)
@click.option("--reinit", is_flag=True, help="Force re-initialization")
@click.option(
    "--skip-key-gen",
    is_flag=True,
    help="Skip first key generation",
)
def init(token: Optional[str], kid: str, quick: bool, reinit: bool, skip_key_gen: bool):
    """Initialize PANDA in your project."""
    panda_dir = get_panda_dir()

    # Check if already initialized
    if not reinit and credentials_exist():
        click.echo("⚠️  PANDA already initialized in this project.")
        click.echo("Use --reinit to force re-initialization.")
        click.echo("Run 'panda status' to see current configuration.")
        return

    # Non-interactive path. This SDK had none: `panda init` always prompted
    # for the key provider and the key identifier, so there was no one-liner
    # for a CI pipeline, a Dockerfile or a provisioning script — while
    # panda-node, panda-php and panda-go all had `--quick`. A documented
    # workflow that works in three SDKs and not the fourth is a workflow that
    # is wrong for whoever picked this one.
    if quick:
        _run_quick_init(token, kid, skip_key_gen)
        return

    # Get token
    if not token:
        token = click.prompt(
            "Enter your PANDA access token (or press Enter to skip)",
            hide_input=True,
            default="",
            show_default=False,
        )

    # Validate: format first, then the portal.
    #
    # This SDK used to stop after the format check. The other three POST the
    # token to the portal and fail closed if it cannot be reached, so a token
    # that had been revoked, one already activated by another application, and
    # one that was never issued all initialised successfully here. It was a
    # gate in appearance only — and the format check is the weaker half, since
    # a well-formed token is exactly what an unauthorised caller would have.
    #
    # The shape follows panda-php: a failure is reported and the user is asked
    # whether to continue, defaulting to no. Skipping remains possible — with
    # the demo token, or with PANDA_SKIP_ONLINE_VALIDATION=1 for tests — but it
    # is now a decision the user makes rather than one nobody was asked.
    if token:
        try:
            validate_token(token)
            click.echo("✓ Token format validated")
        except InvalidTokenError as exc:
            click.echo(f"⚠️  Token validation failed: {exc}")
            if not click.confirm("Continue anyway?", default=False):
                click.echo("Initialization cancelled.")
                return

        if is_demo_token(token) and not is_local_environment():
            click.echo("⚠️  WARNING: You are using the static DEMO TOKEN outside a local development environment.")
            click.echo("Please register your application at the PANDA portal to obtain a per-application live token.")

    # Select key provider
    click.echo("\nSelect key provider:")
    click.echo("  1. Local (environment variables)")
    click.echo("  2. HashiCorp Vault")
    click.echo("  3. Infisical")

    provider_choice = click.prompt("Enter choice (1-3)", type=int, default=1)

    credentials = PandaCredentials(token=token)

    if provider_choice == 2:
        # Vault configuration
        credentials.provider = "vault"
        click.echo("\nConfiguring HashiCorp Vault...")
        credentials.vault_url = click.prompt("Vault URL", default="http://localhost:8200")

        # Authentication method selection
        click.echo("\nSelect Vault authentication method:")
        click.echo("  1. AppRole (Recommended - Auto-renewal, production-ready)")
        click.echo("  2. Token (Advanced - Manual renewal)")

        auth_choice = click.prompt("Choose method", type=int, default=1)

        if auth_choice == 1:
            # AppRole authentication
            credentials.vault_auth_method = "approle"
            click.echo("\nUsing AppRole authentication (auto-renewal enabled)")
            credentials.vault_role_id = click.prompt("Role ID")
            credentials.vault_secret_id = click.prompt("Secret ID", hide_input=True)

            # Optional: Token TTL
            click.echo("\nToken TTL (Optional)")
            click.echo("  Token lifetime before auto-renewal. Default: 3600s (1 hour)")
            click.echo("  Press Enter to use default, or enter custom value (300-86400 seconds)")
            token_ttl_input = click.prompt("Token TTL in seconds", default="3600", show_default=False)
            credentials.vault_token_ttl = int(token_ttl_input) if token_ttl_input else 3600
        else:
            # Token authentication
            credentials.vault_auth_method = "token"
            click.echo("\nUsing Token authentication (manual renewal required)")
            credentials.vault_token = click.prompt("Vault Token", hide_input=True)

        credentials.vault_mount = click.prompt("Mount path", default="secret")

    elif provider_choice == 3:
        # Infisical configuration
        credentials.provider = "infisical"
        credentials.infisical_site_url = click.prompt(
            "Infisical Site URL",
            default="https://app.infisical.com"
        )
        credentials.infisical_client_id = click.prompt("Machine Identity Client ID")
        credentials.infisical_client_secret = click.prompt("Machine Identity Client Secret", hide_input=True)
        credentials.infisical_project_id = click.prompt("Project ID")
        credentials.infisical_environment = click.prompt("Environment", default="dev")
        credentials.infisical_cache_ttl = click.prompt("Cache TTL (seconds)", type=int, default=300)

    # Default Key ID
    default_kid = click.prompt("Default Key ID", default="default-key")
    credentials.default_kid = default_kid

    # Generate key for local provider. `--skip-key-gen` applies here as it
    # does in panda-go and panda-php, which honour it on both paths — a flag
    # that works in the wizard and not in quick mode, or the reverse, is a
    # difference nobody discovers until they need it.
    if credentials.provider == "local" and not skip_key_gen:
        click.echo(f"\nGenerating local key for: {default_kid}")
        env_var_name = _write_local_key(default_kid)
        click.echo(f"✓ Key written to .env as {env_var_name}")
        click.echo("⚠️  IMPORTANT: Store .env securely and never commit it to version control!")

    # Save credentials
    write_credentials(credentials)
    click.echo(f"\n✓ PANDA initialized with {credentials.provider} provider")
    click.echo(f"✓ Configuration saved to {PANDA_DIR_NAME}/")
    click.echo("\nNext steps:")
    click.echo("  - Use 'panda generate <kid>' to create additional keys")
    click.echo("  - Use 'panda status' to verify configuration")


def _write_local_key(kid: str) -> str:
    """Generate a 32-byte key and write it to .env and .env.example.

    Shared by the wizard and quick mode rather than written twice. The two
    paths producing slightly different files — one with PANDA_DEFAULT_KID and
    one without, one appending and one truncating — is how a project ends up
    with a `.env` whose shape depends on which command created it.

    Returns the environment variable name the key was written under.
    """
    key_base64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")

    env_file = Path.cwd() / ".env"
    env_example = Path.cwd() / ".env.example"

    normalized_kid = kid.replace("-", "_").replace(".", "_").upper()
    env_var_name = f"PANDA_KEY_{normalized_kid}"

    for path in [env_file, env_example]:
        with open(path, "a" if path.exists() else "w", encoding="utf-8") as f:
            value = key_base64 if path == env_file else ""
            f.write(f"{env_var_name}={value}\n")
            f.write(f"PANDA_DEFAULT_KID={kid if path == env_file else ''}\n")

    return env_var_name


def _run_quick_init(token: Optional[str], kid: str, skip_key_gen: bool = False) -> None:
    """Non-interactive init: local provider, one key, no prompts.

    Mirrors `--quick` in panda-node, panda-php and panda-go. The token gate
    here is **fail-closed with no override**: the wizard can offer
    "Continue anyway?" because a person is there to answer, and this path
    cannot ask.
    """
    token = token or os.environ.get("PANDA_ACCESS_TOKEN", "")
    if not token:
        click.echo(
            "Error: --quick requires a token.\n"
            "Pass --token <value> or set the PANDA_ACCESS_TOKEN environment variable."
        )
        sys.exit(1)

    try:
        validate_token(token)
    except InvalidTokenError as exc:
        click.echo(f"Error: token gate failed: {exc}")
        sys.exit(1)

    if is_demo_token(token) and not is_local_environment():
        click.echo("⚠️  WARNING: You are using the static DEMO TOKEN outside a local development environment.")
        click.echo("Please register your application at the PANDA portal to obtain a per-application live token.")

    click.echo("✓ Token validated")

    kid = (kid or "").strip() or "default-key"

    credentials = PandaCredentials(token=token, provider="local", default_kid=kid)

    env_var_name = ""
    if not skip_key_gen:
        click.echo(f"Generating local key for: {kid}")
        env_var_name = _write_local_key(kid)

    write_credentials(credentials)

    if not skip_key_gen:
        click.echo(f"✓ Key written to .env as {env_var_name}")
        click.echo("⚠️  IMPORTANT: Store .env securely and never commit it to version control!")
    click.echo(f"\n✓ PANDA initialized with {credentials.provider} provider")
    click.echo(f"✓ Configuration saved to {PANDA_DIR_NAME}/")
    click.echo("\nNext steps:")
    click.echo("  - Use 'panda generate <kid>' to create additional keys")
    click.echo("  - Use 'panda status' to verify configuration")


@cli.command()
@click.argument("kid", required=False)
@click.option("--description", help="Key description")
def generate(kid: Optional[str], description: Optional[str]):
    """Generate a new encryption key."""
    credentials = read_credentials()
    if not credentials:
        click.echo("Error: PANDA not initialized. Run 'panda init' first.")
        sys.exit(1)

    # Get KID if not provided
    if not kid:
        kid = click.prompt("Enter Key ID (e.g., nik-key)")

    if not kid:
        click.echo("Error: Key ID is required")
        sys.exit(1)

    # Validate KID format
    import re
    if not re.match(r"^[a-zA-Z0-9_-]+$", kid):
        click.echo("Error: Key ID must contain only alphanumeric characters, hyphens, and underscores")
        sys.exit(1)

    click.echo(f"Generating key for: {kid}")

    # Generate key
    key_bytes = secrets.token_bytes(32)
    key_base64 = base64.b64encode(key_bytes).decode("ascii")

    # Store based on provider
    if credentials.provider == "local":
        normalized_kid = kid.replace("-", "_").replace(".", "_").upper()
        env_var_name = f"PANDA_KEY_{normalized_kid}"

        env_file = Path.cwd() / ".env"
        env_example = Path.cwd() / ".env.example"

        with open(env_file, "a", encoding="utf-8") as f:
            f.write(f"{env_var_name}={key_base64}\n")

        with open(env_example, "a", encoding="utf-8") as f:
            f.write(f"{env_var_name}=\n")

        click.echo(f"✓ Key stored in .env as {env_var_name}")

    elif credentials.provider == "vault":
        click.echo(f"\nTo store this key in Vault, use:")
        click.echo(f"  vault kv put {credentials.vault_mount or 'secret'}/{kid} value={key_base64}")

    elif credentials.provider == "infisical":
        click.echo("\nStoring key in Infisical...")
        try:
            import urllib.parse
            import http.client

            # Authenticate
            auth_url = f"{credentials.infisical_site_url}/api/v1/auth/universal-auth/login"
            parsed_auth = urllib.parse.urlparse(auth_url)

            conn = http.client.HTTPSConnection(
                parsed_auth.hostname,
                parsed_auth.port or 443,
                timeout=10
            )

            payload = json.dumps({
                "clientId": credentials.infisical_client_id,
                "clientSecret": credentials.infisical_client_secret
            })

            conn.request("POST", parsed_auth.path, body=payload, headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            })

            response = conn.getresponse()
            body = response.read().decode("utf-8")

            if response.status != 200:
                click.echo(f"⚠️  Authentication failed (HTTP {response.status})")
                click.echo(f"Please create the secret manually in Infisical:")
                click.echo(f"  Path: {kid}")
                click.echo(f"  Value (base64): {key_base64}")
                conn.close()
                return

            data = json.loads(body)
            access_token = data.get("accessToken")
            conn.close()

            # Create secret
            api_url = f"{credentials.infisical_site_url}/api/v3/secrets"
            parsed_api = urllib.parse.urlparse(api_url)

            conn = http.client.HTTPSConnection(
                parsed_api.hostname,
                parsed_api.port or 443,
                timeout=10
            )

            secret_payload = json.dumps({
                "projectId": credentials.infisical_project_id,
                "environment": credentials.infisical_environment,
                "secretPath": kid,
                "secretValue": key_base64,
                "type": "shared"
            })

            conn.request("POST", parsed_api.path, body=secret_payload, headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}"
            })

            response = conn.getresponse()
            conn.close()

            if response.status in (200, 201):
                click.echo(f"✓ Key stored in Infisical at path: {kid}")
            else:
                click.echo(f"⚠️  Failed to store (HTTP {response.status})")
                click.echo(f"Please create manually: Path={kid}, Value={key_base64}")

        except Exception as e:
            click.echo(f"⚠️  Failed to store in Infisical: {e}")
            click.echo(f"Please create manually: Path={kid}, Value={key_base64}")

    # Update credentials with new key
    if credentials.keys is None:
        credentials.keys = {}
    credentials.keys[kid] = {
        "created": _now_iso(),
        "provider": credentials.provider
    }
    write_credentials(credentials)

    click.echo(f"\n✓ Key '{kid}' generated successfully!")
    click.echo(f"\nTo use this key:")
    click.echo(f"  cipher.encrypt(value, '{kid}')")


@cli.command()
def status():
    """Show PANDA configuration status."""
    credentials = read_credentials()

    if not credentials:
        click.echo("PANDA not initialized.")
        click.echo("Run 'panda init' to get started.")
        return

    click.echo("\nPANDA Status")
    click.echo("=" * 40)
    click.echo(f"Provider: {credentials.provider}")

    if credentials.provider == "vault" and credentials.vault_url:
        click.echo(f"Vault URL: {credentials.vault_url}")
        click.echo(f"Auth Method: {credentials.vault_auth_method or 'token'}")
        if credentials.vault_auth_method == "approle":
            click.echo(f"Role ID: ***configured***")
        else:
            click.echo(f"Token: ***configured***")
        if credentials.vault_token_ttl:
            click.echo(f"Token TTL: {credentials.vault_token_ttl} seconds")
        click.echo(f"Mount Path: {credentials.vault_mount or 'secret'}")

    elif credentials.provider == "infisical":
        click.echo(f"Site URL: {credentials.infisical_site_url}")
        click.echo(f"Project: {credentials.infisical_project_id}")
        click.echo(f"Environment: {credentials.infisical_environment}")

    if credentials.default_kid:
        click.echo(f"Default KID: {credentials.default_kid}")

    if credentials.keys:
        click.echo("\nKeys:")
        for kid, meta in credentials.keys.items():
            created = meta.get("created", "unknown")
            click.echo(f"  • {kid} (created: {created})")

    click.echo()


@cli.command()
def config():
    """Show detailed PANDA configuration."""
    credentials = read_credentials()

    if not credentials:
        click.echo("Error: PANDA not initialized")
        return

    click.echo("\nPANDA Configuration")
    click.echo("=" * 40)

    # Mask sensitive values
    if credentials.token:
        token_preview = credentials.token[:20] + "..." if len(credentials.token) > 20 else credentials.token
        click.echo(f"Token: {token_preview}")

    click.echo(f"Provider: {credentials.provider}")
    click.echo(f"Default KID: {credentials.default_kid or 'None'}")

    if credentials.provider == "vault":
        click.echo(f"\nVault:")
        click.echo(f"  URL: {credentials.vault_url}")
        click.echo(f"  Auth: {credentials.vault_auth_method or 'token'}")
        if credentials.vault_auth_method == "approle":
            click.echo(f"  Role ID: ***configured***")
        else:
            click.echo(f"  Token: ***configured***")
        if credentials.vault_token_ttl:
            click.echo(f"  Token TTL: {credentials.vault_token_ttl} seconds")
        click.echo(f"  Mount: {credentials.vault_mount or 'secret'}")

    elif credentials.provider == "infisical":
        click.echo(f"\nInfisical:")
        click.echo(f"  Site URL: {credentials.infisical_site_url}")
        click.echo(f"  Client ID: {credentials.infisical_client_id}")
        click.echo(f"  Project ID: {credentials.infisical_project_id}")
        click.echo(f"  Environment: {credentials.infisical_environment}")
        click.echo(f"  Cache TTL: {credentials.infisical_cache_ttl or 300}s")

    if credentials.keys:
        click.echo(f"\nKeys ({len(credentials.keys)}):")
        for kid, meta in credentials.keys.items():
            click.echo(f"  - {kid}")

    click.echo()


@cli.command()
@click.option("--force", is_flag=True, help="Force removal without confirmation")
def deinit(force: bool):
    """Remove PANDA from this project."""
    if not credentials_exist():
        click.echo("PANDA not initialized.")
        return

    if not force:
        if not click.confirm("This will remove PANDA configuration. Continue?"):
            return
        click.echo("\n⚠️  WARNING: Encrypted data in your database will NOT be affected,")
        click.echo("         but you won't be able to decrypt without the keys!")
        if not click.confirm("Continue anyway?"):
            return

    panda_dir = get_panda_dir()

    # Remove .panda directory
    import shutil
    if panda_dir.exists():
        shutil.rmtree(panda_dir)

    # Remove PANDA entries from .env
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        lines = []
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("PANDA_"):
                    lines.append(line)

        with open(env_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

    click.echo("✓ PANDA removed from project")


def _now_iso() -> str:
    """Get current time in ISO format."""
    from datetime import datetime
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _configure_output_encoding() -> None:
    """Stop the CLI dying on a console that cannot encode its own output.

    Nearly every message this tool prints starts with a tick or a warning sign
    — ✓ and ⚠️ — and on a console whose encoding is cp1252, printing one raises
    UnicodeEncodeError and kills the command outright. `panda init` therefore
    failed at its first success message on a default Windows terminal: the
    platform this project's users are most likely to be on, running the one
    workflow the documentation opens with.

    UTF-8 with errors="replace", rather than errors="replace" alone. Where the
    terminal can render the tick it now does; where it cannot, one character
    degrades to a placeholder and the rest of the message still arrives. The
    alternative — keeping the console's encoding and replacing — loses the tick
    on every Windows console, including the ones that could have shown it.

    Streams that are not a TextIOWrapper have no `reconfigure` and are left
    alone, which is what keeps this from touching a test runner's capture
    object.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # A detached stream, or one that refuses to be reconfigured.
            # Neither is worth failing a CLI over.
            pass


def main():
    """Main entry point for the CLI."""
    _configure_output_encoding()
    cli()


if __name__ == "__main__":
    main()
