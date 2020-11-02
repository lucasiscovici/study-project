# type: ignore[attr-defined]

from typing import Optional

import random
from enum import Enum

import typer
from rich.console import Console
from study_project import __version__
from study_project.example import hello
from study_project.study_project import StudyProjectEnv


class Color(str, Enum):
    white = "white"
    red = "red"
    cyan = "cyan"
    magenta = "magenta"
    yellow = "yellow"
    green = "green"


app = typer.Typer(
    name="study-project",
    help="DataScience and ML Management",
    add_completion=False,
)
console = Console()


def version_callback(value: bool):
    """Prints the version of the package."""
    if value:
        console.print(
            f"[yellow]study-project[/] version: [bold blue]{__version__}[/]"
        )
        raise typer.Exit()


@app.command()
def init(
    data_path: str = StudyProjectEnv.data_path,
    project_path: str = StudyProjectEnv.project_path,
):
    StudyProjectEnv.data_path = data_path
    StudyProjectEnv.project_path = project_path
    StudyProjectEnv.check_all_installed()


@app.command(name="")
def main(
    name: str = typer.Option(..., help="Name of person to greet."),
    color: Optional[Color] = typer.Option(
        None,
        "-c",
        "--color",
        "--colour",
        case_sensitive=False,
        help="Color for name. If not specified then choice will be random.",
    ),
    version: bool = typer.Option(
        None,
        "-v",
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Prints the version of the study-project package.",
    ),
):
    """Prints a greeting for a giving name."""
    if color is None:
        # If no color specified use random value from `Color` class
        color = random.choice(list(Color.__members__.values()))

    greeting: str = hello(name)
    console.print(f"[bold {color}]{greeting}[/]")
