# dmarc-import :postal_horn: :mailbox: #

[![Build Status](https://travis-ci.org/dhs-ncats/cyhy-mailer.svg?branch=develop)](https://travis-ci.org/dhs-ncats/cyhy-mailer)
[![Coverage Status](https://coveralls.io/repos/github/dhs-ncats/cyhy-mailer/badge.svg?branch=develop)](https://coveralls.io/github/dhs-ncats/cyhy-mailer?branch=develop)

`dmarc-import` is a tool for parsing DMARC aggregate reports.  The
expected format of these aggregate reports is described in
[RFC 7489](https://tools.ietf.org/html/rfc7489#section-7.2.1.1).

## Installation ##

After using `git` to clone the repository, you can install
`dmarc-import` using `pip`:
```bash
pip install /path/to/dmarc-import
```

Or, if you prefer, you can install directly from
[the GitHub repository](https://github.com/dhs-ncats/dmarc-import):
```bash
pip install git+https://github.com/dhs-ncats/dmarc-import.git
```

Alternatively, you can choose to build the Docker image:
```bash
docker-compose build
```

## Usage ##

```bash
Usage:
  dmarc-import [--s3-bucket=BUCKET] [--s3-keys=KEYS] [--schema=SCHEMA] [--domains=FILE] [--reports=DIRECTORY] [--debug]
  dmarc-import (-h | --help)

Options:
  -h --help           Show this message.
  -d --debug          If specified, then the output will include debugging 
                      messages.
  --s3-bucket=BUCKET  The AWS S3 bucket containing the DMARC aggregate reports.
  --s3-keys=KEYS      A comma-separated list of DMARC aggregate report keys.  
                      If specified, only the specified DMARC aggregate reports 
                      will be processed.  Otherwise all reports in the AWS S3 
                      bucket will be processed.
  --schema=SCHEMA     The XSD file against which the DMARC aggregate reports 
                      are to be be verified.
  --domains=FILE      A file to which to save a list of all domains for which 
                      DMARC aggregate reports were received.  If not specified 
                      then no such file will be created.
  --reports=DIRECTORY A directory to which to write files containing DMARC 
                      aggregate report contents.  If not specified then no 
                      such files will be created.
```

## Setting up Docker secrets ##

Before attempting to run this project via `docker-compose`, you must
create a `secrets` directory and a few files inside it that contain
credentials for the Docker container to use.  These files are:
* `secrets/aws/config` - [an ini format file containing the AWS
  configuration](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)
* `secrets/aws/credentials` - [an ini format file containing the AWS
  credentials](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)

## License ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
