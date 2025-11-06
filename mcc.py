#!/usr/bin/env python3
import sys
import os
import subprocess
from pathlib import Path
import toml
from rich.table import Table
from rich.console import Console
from rich import box

console = Console()
MODAL_TOML = Path(os.path.expanduser("~/.modal.toml"))
DATA_FILE_DIR = Path("data")

def load_modal_config():
    if not MODAL_TOML.exists():
        console.print("[red]Error: ~/.modal.toml not found! Is Modal CLI installed?[/red]")
        sys.exit(1)
    data = toml.load(MODAL_TOML)
    profiles = {}
    active = None
    for section, config in data.items():
        if isinstance(config, dict) and 'token_id' in config:
            profiles[section] = config
            if config.get("active") is True:
                active = section
    return profiles, active

def list_accounts():
    profiles, active = load_modal_config()
    table = Table(title="Modal Users", box=box.ROUNDED, show_lines=True)
    table.add_column("Status", width=8)
    table.add_column("Profile", style="bold magenta")
    table.add_column("Token ID", style="dim")
    table.add_column("Has ENC File", style="green")

    for name in sorted(profiles.keys()):
        status = "•" if name == active else " "
        token_id = profiles[name].get("token_id", "")[:20] + "..."
        enc_file = f"{DATA_FILE_DIR / name}-data.json.enc"
        has_enc = "Yes" if Path(enc_file).exists() else "No"
        table.add_row(status, name, token_id, has_enc)

    console.print(table)
    if active:
        console.print(f"\nCurrent active: [bold yellow]{active}[/bold yellow]")
    else:
        console.print("\n[yellow]No active profile[/yellow]")

def get_current():
    _, active = load_modal_config()
    if active:
        enc_file = f"{DATA_FILE_DIR / active}-data.json.enc"
        has_enc = Path(enc_file).exists()
        status = f"[bold green]{active}[/bold green]"
        if has_enc:
            status += f"  (ENC: {enc_file})"
        console.print(f"Current active profile: {status}")
    else:
        console.print("[red]No active profile[/red]")

def select_profile(name):
    profiles, _ = load_modal_config()
    if name not in profiles:
        console.print(f"[red]Profile '{name}' not found![/red]")
        return
    result = subprocess.run(f"modal profile activate {name}", shell=True)
    if result.returncode == 0:
        console.print(f"[green]Activated: {name}[/green]")
    else:
        console.print(f"[red]Failed to activate {name}[/red]")

def deploy_profile(name):
    profiles, _ = load_modal_config()
    if name not in profiles:
        console.print(f"[red]Profile '{name}' not found in ~/.modal.toml[/red]")
        sys.exit(1)

    enc_file = f"{DATA_FILE_DIR / name}-data.json.enc"
    if not Path(enc_file).exists():
        console.print(f"[red]Error: {enc_file} not found in current directory![/red]")
        console.print("   Please make sure the encrypted file exists.")
        sys.exit(1)

    cmd = f"modal profile activate {name} && ENC_PATH={enc_file} modal deploy serve_modal.py"
    console.print(f"[bold blue]Deploying {name} ...[/bold blue]")
    console.print(f"[dim]$ {cmd}[/dim]\n")
    os.system(cmd)

def list_apps_in_profile(target_profile=None):
    profiles, current_active = load_modal_config()

    if target_profile and target_profile not in profiles:
        console.print(f"[red]Profile '{target_profile}' not found![/red]")
        return

    # 如果指定了 profile 且不是当前活跃的，先切换
    need_switch_back = False
    if target_profile and target_profile != current_active:
        console.print(f"[dim]Temporarily switching to {target_profile} ...[/dim]")
        activate_result = subprocess.run(f"modal profile activate {target_profile}", shell=True, capture_output=True, text=True)
        if activate_result.returncode != 0:
            console.print(f"[red]Failed to switch to {target_profile}[/red]")
            console.print(activate_result.stderr)
            return
        need_switch_back = True

    # 执行 modal app list
    profile_name = target_profile or current_active or "current"
    console.print(f"\n[bold cyan]=== Apps in {profile_name} ===[/bold cyan]\n")
    os.system("modal app list")

    # 切回原账号
    if need_switch_back and current_active:
        console.print(f"\n[dim]Switching back to {current_active} ...[/dim]")
        subprocess.run(f"modal profile activate {current_active}", shell=True)

def print_help():
    help_text = """
[bold]./mcc.py[/bold] - Modal 账号快速切换工具

[bold]Usage:[/bold]
  ./mcc.py                    Show current active profile
  ./mcc.py users              List all profiles
  ./mcc.py select <name>      Activate a profile
  ./mcc.py deploy <name>      Activate + deploy with {name}-data.json.enc
  ./mcc.py apps               List apps in current profile
  ./mcc.py apps <name>        Temporarily switch to <name>, list apps, then switch back

[bold]Examples:[/bold]
  ./mcc.py
  ./mcc.py users
  ./mcc.py apps
  ./mcc.py apps firelion0668
  ./mcc.py deploy neeohe
    """
    console.print(help_text)

def main():
    if len(sys.argv) == 1:
        get_current()
        return

    cmd = sys.argv[1].lower()

    if cmd in ["-h", "--help", "help"]:
        print_help()
        return

    if cmd == "users":
        list_accounts()
        return

    if cmd == "apps":
        # ./mcc.py apps [profile]
        profile = sys.argv[2] if len(sys.argv) > 2 else None
        list_apps_in_profile(profile)
        return

    if len(sys.argv) < 3:
        console.print(f"[red]Missing profile name for '{cmd}'[/red]")
        print_help()
        return

    profile = sys.argv[2]

    if cmd == "select":
        select_profile(profile)
    elif cmd == "deploy":
        deploy_profile(profile)
    else:
        console.print(f"[red]Unknown command: {cmd}[/red]")
        print_help()

if __name__ == "__main__":
    try:
        import toml
    except ImportError:
        try:
            import tomllib as toml
        except ImportError:
            console.print("[red]Please install toml: pip install toml[/red]")
            sys.exit(1)
    main()