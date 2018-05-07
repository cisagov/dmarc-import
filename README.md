# dmarc-import :postal_horn: :mailbox: #

[![Build Status](https://travis-ci.org/dhs-ncats/dmarc-import.svg?branch=develop)](https://travis-ci.org/dhs-ncats/dmarc-import)
[![Coverage Status](https://coveralls.io/repos/github/dhs-ncats/dmarc-import/badge.svg?branch=develop)](https://coveralls.io/github/dhs-ncats/dmarc-import?branch=develop)

`dmarc-import` is a tool for parsing DMARC aggregate reports.  The
expected format of these aggregate reports is described in
[RFC 7489](https://tools.ietf.org/html/rfc7489#section-7.2.1.1).

## Installation of the Python package ##

### From PyPI ###

```bash
pip install dmarc-import
```

### From your local checkout ###
After using `git` to clone the repository, you can install
`dmarc-import` using `pip`:
```bash
pip install /path/to/dmarc-import
```

### From GitHub ###
Or, if you prefer, you can install directly from
[the GitHub repository](https://github.com/dhs-ncats/dmarc-import):
```bash
pip install git+https://github.com/dhs-ncats/dmarc-import.git
```

## Building the Docker image ##

As an alternative to installing the Python package, you can instead
choose to build the Docker image:
```bash
docker-compose build
```

## Usage ##

```bash
Usage:
  dmarc-import --schema=SCHEMA --s3-bucket=BUCKET [--s3-keys=KEYS] [--domains=FILE] [--reports=DIRECTORY] [--elasticsearch=URL] [--es-region=REGION] [--log-level=LEVEL] [--dmarcian-token=FILE] [--delete]
  dmarc-import (-h | --help)

Options:
  -h --help               Show this message.
  --log-level=LEVEL       If specified, then the log level will be set to the
                          specified value.  Valid values are "debug", "info",
                          "warn", and "error".
  --schema=SCHEMA         The XSD file against which the DMARC aggregate
                          reports are to be be verified.
  --s3-bucket=BUCKET      The AWS S3 bucket containing the DMARC aggregate
                          reports.
  --s3-keys=KEYS          A comma-separated list of DMARC aggregate report
                          keys.  If specified, only the specified DMARC
                          aggregate reports will be processed.  Otherwise all
                          reports in the AWS S3 bucket will be processed.
  --domains=FILE          A file to which to save a list of all domains for
                          which DMARC aggregate reports were received.  If not
                          specified then no such file will be created.
  --reports=DIRECTORY     A directory to which to write files containing DMARC
                          aggregate report contents.  If not specified then no
                          such files will be created.
  --elasticsearch=URL     A URL corresponding to an AWS Elasticsearch
                          instance, including the index where the DMARC
                          aggregate reports should be written.
  --es-region=REGION      The AWS region where the Elasticsearch instance
                          is located.
  --dmarcian-token=FILE   A simple text file whose only contents are the
                          Dmarcian API token.  If specified then the
                          Dmarcian API will be queried to determine what
                          commercial mail-sending organization (if any) is
                          associated with the IP in the aggregate report.
  --delete                If present then the reports will be deleted after
                          processing.
```

## Setting up Docker secrets ##

Before attempting to run this project via `docker-compose`, you must
create a `secrets` directory and a few files inside it that contain
credentials for the Docker container to use.  These files are:
* `secrets/aws/config` - [an ini format file containing the AWS
  configuration](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)
* `secrets/aws/credentials` - [an ini format file containing the AWS
  credentials](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)
* `secrets/dmarcian/token` - a text file containing a [Dmarcian API
  token](https://dmarcian.com/)

## License ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
