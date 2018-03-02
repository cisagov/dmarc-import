from setuptools import setup, find_packages

setup(
    name='dmarc_import',
    version='0.0.1',
    author='Mark Feldhousen Jr.',
    author_email='mark.feldhousen@hq.dhs.gov',
    packages=['dmarc'],
    include_package_data=True,
    zip_safe=False,
    #scripts=['bin/foo'],
    entry_points={
        'console_scripts': [
          'dmarc-s3-import=dmarc.s3:main',
        ],
    },
    license='LICENSE.txt',
    description='DMARC Record Importer',
    long_description=open('README.md').read(),
    install_requires=[
        "docopt >= 0.6.2",
        "lxml == 4.1.1",
        "boto3 >= 1.4.7"
    ]
)
