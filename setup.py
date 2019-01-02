import os
from setuptools import setup, find_packages


VERSION = '0.6.0'


def read(fname):
    """ Returns the contents of the fname file """
    with open(os.path.join(os.path.dirname(__file__), fname), 'r') as file:
        return file.read()


# Available classifiers: https://pypi.org/pypi?%3Aaction=list_classifiers
CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: Apache Software License',
    'Topic :: Office/Business :: Office Suites',
    'Topic :: Software Development :: Libraries',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3 :: Only',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Operating System :: OS Independent',
]


requires = ['Flask']

setup(
    name='flask-session-plus',
    version=VERSION,
    packages=find_packages(),
    url='https://github.com/janscas/flask-session-plus',
    license='Mit License',
    author='Janscas',
    author_email='janscas@users.noreply.github.com',
    maintainer='Janscas',
    maintainer_email='janscas@users.noreply.github.com',
    description='Flask Multiple Sessions Interface (combine multiple sessions with different backends)',
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    classifiers=CLASSIFIERS,
    python_requires=">=3.4",
    install_requires=requires,
)
