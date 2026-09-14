import typer
from auto_remediate import __version__

app = typer.Typer(name="auto-remediate", help="DevSecOps Auto-Remediation CLI")

@app.command()
def version():
    typer.echo(f"auto-remediate v{__version__}")

if __name__ == "__main__":
    app()
