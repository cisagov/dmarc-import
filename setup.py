from setuptools import setup, find_packages

from dmarc import __version__

setup(
    name='dmarc-import',
    version=__version__,
    description='A tool for parsing DMARC aggregate reports.',
    long_description=open('README.md').read(),

    # NCATS "homepage"
    url='https://www.dhs.gov/cyber-incident-response',
    # The project's main homepage
    download_url='https://github.com/dhs-ncats/dmarc-import',

    # Author details
    author='Department of Homeland Security, National Cybersecurity Assessments and Technical Services team',
    author_email='ncats@hq.dhs.gov',

    license='License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    # What does your project relate to?
    keywords='dmarc,rua',

    packages=['dmarc'],

    install_requires=[
        'docopt >= 0.6.2',
        'lxml == 4.1.1',
        'boto3 >= 1.4.7'
    ],

    extras_require={
        # 'dev': ['check-manifest'],
        'test': [
            'tox',
            'pytest'
        ],
    },

    entry_points={
        'console_scripts': [
            'dmarc-s3-import = dmarc.s3:main'
        ]
    }
)
