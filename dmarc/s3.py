#!/usr/bin/env python3

"""dmarc-import: A tool for parsing DMARC aggregate reports.  The
expected format of these aggregate reports is described in RFC 7489
(https://tools.ietf.org/html/rfc7489#section-7.2.1.1).

Usage:
  dmarc-import --schema=SCHEMA --s3-bucket=BUCKET [--s3-keys=KEYS] [--domains=FILE] [--reports=DIRECTORY] [--debug]
  dmarc-import (-h | --help)

Options:
  -h --help           Show this message.
  -d --debug          If specified, then the output will include debugging
                      messages.
  --schema=SCHEMA     The XSD file against which the DMARC aggregate reports
                      are to be be verified.
  --s3-bucket=BUCKET  The AWS S3 bucket containing the DMARC aggregate reports.
  --s3-keys=KEYS      A comma-separated list of DMARC aggregate report keys.
                      If specified, only the specified DMARC aggregate reports
                      will be processed.  Otherwise all reports in the AWS S3
                      bucket will be processed.
  --domains=FILE      A file to which to save a list of all domains for which
                      DMARC aggregate reports were received.  If not specified
                      then no such file will be created.
  --reports=DIRECTORY A directory to which to write files containing DMARC
                      aggregate report contents.  If not specified then no
                      such files will be created.
"""

import binascii
import email
import gzip
import io
import logging
import re
import zipfile

import boto3
import docopt
from lxml import etree

from dmarc import __version__


def pp(tree):
    print(etree.tostring(tree, pretty_print=True).decode())


def pp_parse_error(payload, e):
    logging.error(e.error_log)
    line_num = 1
    for line in payload.splitlines():
        logging.error('%d\t%s' % (line_num, line))
        line_num += 1


def parse_payload(payload):
    try:
        tree = etree.fromstring(payload)
    except etree.XMLSyntaxError as e:
        pp_parse_error(payload, e)
        return None
    return tree


def patch_xml(payload):
    '''The rua schema needs some fixing'''
    patched = re.sub(b'<feedback.*?>', b'<provider:feedback xmlns:provider="http://dmarc.org/dmarc-xml/0.1">', payload)
    patched = re.sub(b'</feedback>', b'</provider:feedback>', patched)
    return patched


def decode_payload(content_type, payload):
    logging.debug('\t' + content_type + '\t size:' + str(len(payload)))
    if content_type in ['application/x-zip-compressed', 'application/zip']:
        zip_bytes = io.BytesIO(payload)
        zip_file = zipfile.ZipFile(zip_bytes)
        extracted_file = zip_file.open(zip_file.namelist()[0])
        payload = extracted_file.read()
    elif content_type in ['application/gzip']:
        payload = gzip.decompress(payload)
    elif content_type in ['text/xml']:
        pass  # TODO: log
    else:
        return None  # TODO: log
    return payload


class Parser:
    schema = None
    # parser = None

    def __init__(self, schema_file):
        self.schema = etree.XMLSchema(file=schema_file)
        # self.parser = etree.XMLParser(schema=schema)

    def pp_validation_error(self, tree):
        logging.error(self.schema.error_log)
        line_num = 2  # Dunno, it lines up with error messages
        for line in etree.tostring(tree).decode().splitlines():
            logging.error('%d\t%s' % (line_num, line))
            line_num += 1

    def process_message(self, message):
        if message.is_multipart():
            # Loop through message parts
            for part in message.get_payload():
                try:
                    xml = self.process_payload(part.get_content_type(), part.get_payload(decode=True))
                except (binascii.Error, AssertionError) as e:
                    logging.error('Caught an exception', e)
        else:
            # This isn't a multipart message
            try:
                xml = self.process_payload(message.get_content_type(), message.get_payload(decode=True))
            except (binascii.Error, AssertionError) as e:
                logging.error('Caught an exception', e)

        return xml

    def process_payload(self, content_type, payload):
        if payload is None:
            return
        payload = decode_payload(content_type, payload)
        if payload is None:
            return
        patched = patch_xml(payload)
        tree = parse_payload(patched)
        if tree is None:
            logging.error('RUA payload FAILED xml parsing')
            return None

        valid = self.schema.validate(tree)
        if valid:
            logging.debug('RUA payload passed schema validation')
        else:
            logging.error('RUA payload FAILED schema validation')
            self.pp_validation_error(tree)

        return tree


def do_it(obj, parser, domains):
    logging.info('Processing: ' + obj.key)
    body = obj.get()['Body'].read()
    message = email.message_from_bytes(body)
    tree = parser.process_message(message)
    if tree is not None:
        domain = tree.find('policy_published').find('domain').text
        domains.add(domain)

        logging.info('Received a report for {}'.format(domain))


def main():
    # Parse command line arguments
    args = docopt.docopt(__doc__, version=__version__)

    # Set up logging
    log_level = logging.WARNING
    if args['--debug']:
        log_level = logging.DEBUG
    logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s', level=log_level)

    # Get down to business
    parser = Parser(args['--schema'])
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(args['--s3-bucket'])
    domains = set()
    if '--s3-keys' in args and args['--s3-keys']:
        # The user specified the keys
        for key in args['--s3-keys'].split(','):
            do_it(bucket.Object(key.strip()), parser, domains)
    else:
        # The user didn't specify the keys so iterate over all the keys in the
        # bucket
        for obj in bucket.objects.all():
            do_it(obj, parser, domains)

    for d in sorted(list(domains)):
        print(d)

    # Stop logging and clean up
    logging.shutdown()


if __name__ == '__main__':
    main()
