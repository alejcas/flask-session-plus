"""
Release script
"""

import os
import shutil
import subprocess
import sys
import requests
from pathlib import Path

# noinspection PyPackageRequirements
import click


PYPI_PACKAGE_NAME = 'flask-session-plus'
PYPI_URL = 'https://pypi.org/pypi/{package}/json'
DIST_PATH = 'dist'
DIST_PATH_DELETE = 'dist_delete'
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


@cli.command()
@click.option('--force/--no-force', default=False, help='Will force a new build removing the previous ones')
def build(force):
    """ Builds the distribution files: wheels and source. """
    dist_path = Path(DIST_PATH)
    if dist_path.exists() and list(dist_path.glob('*')):
        if force or click.confirm('{} is not empty - delete contents?'.format(dist_path)):
            dist_path.rename(DIST_PATH_DELETE)
            shutil.rmtree(Path(DIST_PATH_DELETE))
            dist_path.mkdir()
        else:
            click.echo('Aborting')
            sys.exit(1)

    subprocess.check_call(['python', 'setup.py', 'bdist_wheel'])
    subprocess.check_call(['python', 'setup.py', 'sdist',
                           '--formats=gztar'])


@cli.command()
@click.option('--release/--no-release', default=False, help='--release to upload to pypi otherwise upload to test.pypi')
@click.option('--rebuild/--no-rebuild', default=True, help='Will force a rebuild of the build files (src and wheels)')
@click.pass_context
def upload(ctx, release, rebuild):
    """ Uploads distribuition files to pypi or pypitest. """

    dist_path = Path(DIST_PATH)
    if rebuild is False:
        if not dist_path.exists() or not list(dist_path.glob('*')):
            print("No distribution files found. Please run 'build' command first")
            return
    else:
        ctx.invoke(build, force=True)

    if release:
        args = ['twine', 'upload', 'dist/*']
    else:
        repository = 'https://test.pypi.org/legacy/'
        args = ['twine', 'upload', '--repository-url', repository, 'dist/*']

    env = os.environ.copy()

    p = subprocess.Popen(args, env=env)
    p.wait()


@cli.command()
def check():
    """ Checks the long description. """
    dist_path = Path(DIST_PATH)
    if not dist_path.exists() or not list(dist_path.glob('*')):
        print("No distribution files found. Please run 'build' command first")
        return

    subprocess.check_call(['twine', 'check', 'dist/*'])


# noinspection PyShadowingBuiltins
@cli.command(name='list')
def list_releases():
    """ Lists all releases published on pypi"""
    response = requests.get(PYPI_URL.format(package=PYPI_PACKAGE_NAME))
    if response:
        data = response.json()

        releases_dict = data.get('releases', {})

        if releases_dict:
            for version, release in releases_dict.items():
                release_formats = []
                published_on_date = None
                for fmt in release:
                    release_formats.append(fmt.get('packagetype'))
                    published_on_date = fmt.get('upload_time')

                release_formats = ' | '.join(release_formats)
                print('{:<10}{:>15}{:>25}'.format(version, published_on_date, release_formats))
        else:
            print('No releases found for {}'.format(PYPI_PACKAGE_NAME))
    else:
        print('Package "{}" not found on Pypi.org'.format(PYPI_PACKAGE_NAME))


if __name__ == "__main__":
    cli()
