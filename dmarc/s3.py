#!/usr/bin/env python3

"""dmarc-import: A tool for parsing DMARC aggregate reports.  The
expected format of these aggregate reports is described in RFC 7489
(https://tools.ietf.org/html/rfc7489#section-7.2.1.1).

Usage:
  dmarc-import --schema=SCHEMA --s3-bucket=BUCKET [--s3-keys=KEYS] [--domains=FILE] [--reports=DIRECTORY] [--debug] [--info] [--delete]
  dmarc-import (-h | --help)

Options:
  -h --help           Show this message.
  --debug             If specified, then the output will include info and
                      debugging messages.
  --info              If specified, then the output will include info messages.
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
  --delete            If present then the reports will be deleted after
                      processing.
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
    """Pretty-print an XML element to standard out.

    Parameters
    ----------
    tree : etree.Element
        The XML element to be pretty-printed.
    """
    print(etree.tostring(tree, pretty_print=True).decode())


def pp_parse_error(payload, e):
    """Pretty-print a parse error to the error log.

    Parameters
    ----------
    payload : str
        The XML string that caused the error.

    e : Exception
        The exception that was raised.
    """
    logging.error(e.error_log)
    line_num = 1
    for line in payload.splitlines():
        logging.error('%d\t%s' % (line_num, line))
        line_num += 1


def parse_payload(payload):
    """Parse the payload as XML.

    Parameters
    ----------
    payload : str
        The XML string to be parsed.

    Returns
    -------
    etree.Element: The XML element that was parsed.
    """
    tree = None
    try:
        tree = etree.fromstring(payload)
    except etree.XMLSyntaxError as e:
        pp_parse_error(payload, e)

    return tree


def patch_xml(payload):
    """Patch the XML payload string so it can be handled by the schema.

    Parameters
    ----------
    payload : str
        The XML string to be patched.

    Returns
    -------
    str: The patched XML string.
    """
    patched = re.sub(b'<feedback.*?>', b'<provider:feedback xmlns:provider="http://dmarc.org/dmarc-xml/0.1">', payload)
    patched = re.sub(b'</feedback>', b'</provider:feedback>', patched)
    return patched


def decode_payload(content_type, payload):
    """Decode the payload extracted from the message into an XML string.

    Parameters
    ----------
    content_type : str
        The content type of the payload.

    payload : str
        The (possibly compressed) payload.

    Returns
    -------
    str: The XML string extracted from the payload.
    """
    logging.debug('Content type is {}, size is {}'.format(content_type, len(payload)))

    if content_type in ['application/x-zip-compressed', 'application/zip']:
        zip_bytes = io.BytesIO(payload)
        zip_file = zipfile.ZipFile(zip_bytes)
        extracted_file = zip_file.open(zip_file.namelist()[0])
        payload = extracted_file.read()
    elif content_type in ['application/gzip']:
        payload = gzip.decompress(payload)
    elif content_type in ['text/xml']:
        logging.warning('XML content not compressed')
        pass
    else:
        logging.error('Unhandled content type {}'.format(content_type))
        payload = None

    return payload


class Parser:
    """Handles the verification and parsing of DMARC aggregate reports

    Attributes
    ----------
    schema : str
        The name of the file containing the XML schema defining a
        DMARC aggregate report.

    domains : io.FileIO
        The file object to which a list of the domains encountered
        while parsing DMARC aggregate reports should be saved, or None
        if no such file is to be saved.

    report_directory : str
        The name of the directory to which XML files containing the
        DMARC aggregate reports encountered while parsing DMARC
        aggregate reports should be saved, or None if no such files
        are to be saved.
    """
    schema = None
    # parser = None
    domains = None
    report_directory = None

    def __init__(self, schema_file, domain_file=None, report_directory=None):
        """Construct a Parser instance.

        Parameters
        ----------
        schema_file : str
            The name of the file containing the XML schema defining a DMARC
            aggregate report.

        domain_file : str
            The name of the file to which a list of the domains
            encountered while parsing DMARC aggregate reports should
            be saved, or None if no such file is to be saved.

        report_directory : str
            The name of the directory to which XML files containing
            the DMARC aggregate reports encountered while parsing
            DMARC aggregate reports should be saved, or None if no
            such files are to be saved.
        """
        self.schema = etree.XMLSchema(file=schema_file)
        # self.parser = etree.XMLParser(schema=schema)
        if domain_file is not None:
            self.domains = open(domain_file, 'w')
        self.report_directory = report_directory

    def pp_validation_error(self, tree):
        """Pretty-print a validation error to the error log.

        Parameters
        ----------
        tree : etree.Element
            The XML element that caused the error.
        """
        logging.error(self.schema.error_log)
        line_num = 2  # Dunno, it lines up with error messages
        for line in etree.tostring(tree).decode().splitlines():
            logging.error('{}\t{}'.format(line_num, line))
            line_num += 1

    def process_message(self, message):
        """Process a (possibly multipart) email message containing one
        or more DMARC aggregate reports.

        Parameters
        ----------
        message : email.message.EmailMessage
            The email message to be processed.
        """
        if message.is_multipart():
            # Loop through message parts
            for part in message.get_payload():
                try:
                    self.process_payload(part.get_content_type(), part.get_payload(decode=True))
                except (binascii.Error, AssertionError) as e:
                    logging.error('Caught an exception', e)
                    continue
        else:
            # This isn't a multipart message
            try:
                self.process_payload(message.get_content_type(), message.get_payload(decode=True))
            except (binascii.Error, AssertionError) as e:
                logging.error('Caught an exception', e)

    def process_payload(self, content_type, payload):
        """Process a (possibly compressed) payload containing an DMARC
        aggregate report.

        Parameters
        ----------
        content_type : str
            The content type of the payload.

        payload : str
            The (possibly compressed) payload.
        """
        if payload is not None:
            decoded_payload = decode_payload(content_type, payload)
            if decoded_payload is not None:
                patched_payload = patch_xml(decoded_payload)
                tree = parse_payload(patched_payload)
                if tree is not None:
                    valid = self.schema.validate(tree)
                    if valid:
                        logging.debug('RUA payload passed schema validation')
                        domain = tree.find('policy_published').find('domain').text
                        logging.info('Received a report for {}'.format(domain))
                        if self.domains:
                            self.domains.write('{}\n'.format(domain))
                        if self.report_directory:
                            report_id = tree.find('report_metadata').find('report_id').text
                            with open('{}/{}.xml'.format(self.report_directory, report_id), 'w') as report_file:
                                report_file.write(etree.tostring(tree, pretty_print=True).decode())
                    else:
                        logging.error('RUA payload FAILED schema validation')
                        self.pp_validation_error(tree)
                else:
                    logging.error('RUA payload FAILED xml parsing')


def process(obj, parser, delete):
    """Process an s3.Object retrieved from an S3 bucket that contains
    a (possibly multipart) email message containing one or more DMARC
    aggregate reports.

    Parameters
    ----------
    obj : s3.Object
        The s3.Object to be processed.

    parser : Parser
        The Parser to use for the processing.

    delete : bool
        Whether or not to delete the s3.Object after processing.
    """
    logging.info('Processing: ' + obj.key)
    body = obj.get()['Body'].read()
    message = email.message_from_bytes(body)
    parser.process_message(message)

    if delete:
        obj.delete()


def main():
    # Parse command line arguments
    args = docopt.docopt(__doc__, version=__version__)

    # Set up logging
    log_level = logging.WARNING
    if args['--debug']:
        log_level = logging.DEBUG
    elif args['--info']:
        log_level = logging.INFO
    logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s', level=log_level)

    # Handle some command line arguments
    delete = False
    if args['--delete']:
        delete = True

    # Get down to business
    parser = Parser(args['--schema'], args['--domains'], args['--reports'])
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(args['--s3-bucket'])
    keys = args['--s3-keys']
    if keys:
        # The user specified the keys
        for key in keys.split(','):
            process(bucket.Object(key.strip()), parser, delete)
    else:
        # The user didn't specify the keys so iterate over all the keys in the
        # bucket
        for obj in bucket.objects.all():
            process(obj, parser, delete)

    # Stop logging and clean up
    logging.shutdown()


if __name__ == '__main__':
    main()
