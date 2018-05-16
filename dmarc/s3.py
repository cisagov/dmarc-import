#!/usr/bin/env python3

"""dmarc-import: A tool for parsing DMARC aggregate reports.  The
expected format of these aggregate reports is described in RFC 7489
(https://tools.ietf.org/html/rfc7489#section-7.2.1.1).

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
"""

import binascii
import email
import gzip
import io
import logging
import re
import sys
import zipfile

import boto3
import docopt
from lxml import etree
import requests
from requests_aws4auth import AWS4Auth
from xmljson import Parker

from dmarc import __version__


def pp(tree):
    """Pretty-print an XML element.

    Parameters
    ----------
    tree : etree.Element
        The XML element to be pretty-printed.

    Returns
    -------
    str: A string containing the pretty-printed XML.

    Throws
    ------
    UnicodeError: If the bytestring representing the XML element
    cannot be decoded as UTF-8.
    """
    return etree.tostring(tree, pretty_print=True).decode()


def pp_parse_error(payload, e):
    """Pretty-print a parse error to the error log.

    Parameters
    ----------
    payload : str
        The XML string that caused the error.

    e : etree.XMLSyntaxError
        The exception indicating a parsing error.
    """
    logging.error(e.error_log)
    line_num = 1
    for line in payload.splitlines():
        logging.error('{}\t{}'.format(line_num, line))
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

    Throws
    ------
    etree.XMLSyntaxError: If the XML string to be parsed does not
    adhere to valid XML syntax.
    """
    return etree.fromstring(payload)


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
    # Technically re.sub() could throw an re.error, but realistically this will
    # never happen here because the regex expressions are hard coded
    patched = re.sub(b'<feedback.*?>',
                     b'<provider:feedback xmlns:provider="http://dmarc.org/dmarc-xml/0.1">', payload)
    patched = re.sub(b'</feedback>', b'</provider:feedback>', patched)
    return patched


def decode_payload(content_type, payload):
    """Decode the payload extracted from the message into an XML
    string.

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
    logging.debug('Content type is {}, size is {}'.format(content_type,
                                                          len(payload)))

    if content_type in ['application/x-zip-compressed', 'application/zip']:
        with io.BytesIO(payload) as zip_bytes:
            try:
                with zipfile.ZipFile(zip_bytes) as zip_file:
                    with zip_file.open(zip_file.namelist()[0]) as extracted_file:
                        decoded_payload = extracted_file.read()
            except zipfile.BadZipFile as e:
                logging.error('Unable to process zip data', e)
    elif content_type in ['application/gzip']:
        decoded_payload = gzip.decompress(payload)
    elif content_type in ['text/xml']:
        logging.warning('XML content not compressed')
        decoded_payload = payload
    else:
        logging.warning('Unhandled content type {}'.format(content_type))
        decoded_payload = None

    return decoded_payload


class Parser:
    """Class that handles the verification and parsing of DMARC
    aggregate reports.

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

    es_url : str
        A URL corresponding to an AWS Elasticsearch instance,
        including the index where DMARC aggregate reports should be
        written.

    es_region : str
        The AWS region where the Elasticsearch instance is located.

    parker : xmljson.Parker
        Converts XML to JSON using the Parker convention.  Since the
        aggregate report XSD does not define any attributes we can use
        this convention to simplify the JSON without losing any
        information.

    api_headers : dict
        The Dmarcian API authentication header.
    """

    """The URL for the Dmarcian API call that retrieves the bulk
    mail-sending organization (if any) associated with an IP.
    """
    __DmarcianApiUrl = 'https://dmarcian.com/api/v1/find/source/{}'

    """The name of the authentication header required by the Dmarcian API"""
    __DmarcianHeaderName = 'Authorization'

    """The value of the authentication header required by the Dmarcian API"""
    __DmarcianHeaderValue = 'Token {}'

    """The timeout in seconds to use when retrieving API data"""
    __Timeout = 300

    def __init__(self, schema_file, domain_file=None, report_directory=None,
                 es_url=None, es_region=None, api_token=None):
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

        es_url : str
            A URL corresponding to an AWS Elasticsearch instance,
            including the index where DMARC aggregate reports should
            be written.

        api_token : str
            The Dmarcian API token.
        """
        self.schema = etree.XMLSchema(file=schema_file)

        if domain_file is not None:
            self.domains = open(domain_file, 'w')
        else:
            self.domains = None

        self.report_directory = report_directory

        self.es_url = es_url
        self.es_region = es_region

        # We don't care about order of dictionary elements here, so we can use
        # a simple dict instead of the default OrderedDict
        self.parker = Parker(dict_type=dict)

        if api_token is not None:
            self.api_headers = {
                Parser.__DmarcianHeaderName: Parser.__DmarcianHeaderValue.format(api_token)
            }
        else:
            self.api_headers = None

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

        Returns
        -------
        bool: True if the message was parsed successfully and False
        otherwise.
        """
        # The binascii.Error and AssertionError that appear below are raised if
        # the payload contains a non-base64 digit.  We'll catch the exceptions
        # here since we want to process any other message parts, but we'll log
        # them and set success to False so that the message isn't deleted.
        success = True
        if message.is_multipart():
            # Loop through message parts
            for part in message.get_payload():
                try:
                    success &= self.process_payload(part.get_content_type(),
                                                    part.get_payload(decode=True))
                except (binascii.Error, AssertionError) as e:
                    logging.error('Unable to process a multipart message payload', e)
                    success = False
                    continue
        else:
            # This isn't a multipart message
            try:
                success = self.process_payload(message.get_content_type(),
                                               message.get_payload(decode=True))
            except (binascii.Error, AssertionError) as e:
                logging.error('Unable to process a non-multipart message payload', e)
                success = False

        return success

    def process_payload(self, content_type, payload):
        """Process a (possibly compressed) payload containing an DMARC
        aggregate report.

        Parameters
        ----------
        content_type : str
            The content type of the payload.

        payload : str
            The (possibly compressed) payload.

        Returns
        -------
        bool: True if the payload was parsed successfully and False
        otherwise.
        """
        success = True
        if payload is not None:
            decoded_payload = decode_payload(content_type, payload)
            if decoded_payload is not None:
                patched_payload = patch_xml(decoded_payload)
                tree = None
                try:
                    tree = parse_payload(patched_payload)
                except etree.XMLSyntaxError as e:
                    pp_parse_error(patched_payload, e)
                    success = False

                if tree is not None:
                    valid = self.schema.validate(tree)
                    if valid:
                        logging.debug('RUA payload passed schema validation')
                        logging.debug('Report XML is: {}'.format(pp(tree)))
                        domain = tree.find('policy_published').find('domain').text
                        logging.info('Received a report for {}'.format(domain))

                        # Write the domain to the domains file if necessary
                        if self.domains is not None:
                            self.domains.write('{}\n'.format(domain))

                        # Write the report to the report directory if necessary
                        if self.report_directory is not None:
                            report_id = tree.find('report_metadata').find('report_id').text
                            with open('{}/{}.xml'.format(self.report_directory, report_id), 'w') as report_file:
                                report_file.write(etree.tostring(tree, pretty_print=True).decode())

                        # Convert the XML to JSON
                        jsn = self.parker.data(tree)

                        # Find the bulk mail-sending organizations (if any)
                        # associated with the IPs in the report.
                        #
                        # jsn['record'] can be a list if there are multiple
                        # record tags in the XML, or a dict if there is only a
                        # single record tag.  Parser.listify() will make sure
                        # that we have a list here.
                        for record in Parser.listify(jsn['record']):
                            if self.api_headers is not None:
                                ip = record['row']['source_ip']
                                url = Parser.__DmarcianApiUrl.format(ip)
                                try:
                                    response = requests.get(url,
                                                            headers=self.api_headers,
                                                            timeout=Parser.__Timeout)
                                    # Raises an exception if we didn't get back
                                    # a 200 code
                                    response.raise_for_status()
                                    record['row']['source_ip_affiliation'] = response.json()[ip]
                                except requests.exceptions.RequestException as e:
                                    logging.exception('Unable to use the Dmarcian API to determine the affiliation of source IP {}'.format(ip))
                                    # We can't query the Dmarcian API because
                                    # of an error, so just add an empty entry
                                    record['row']['source_ip_affiliation'] = None
                                    success = False
                            else:
                                # We can't query the Dmarcian API because we
                                # don't have a token, so just add an empty
                                # entry
                                logging.debug('json is: {}'.format(jsn))
                                logging.debug('record is: {}'.format(record))
                                record['row']['source_ip_affiliation'] = None

                        # Write the report to Elasticsearch if necessary
                        if (self.es_url is not None) and (self.es_region is not None):
                            credentials = boto3.Session().get_credentials()
                            awsauth = AWS4Auth(credentials.access_key,
                                               credentials.secret_key,
                                               self.es_region,
                                               'es',
                                               session_token=credentials.token)
                            try:
                                response = requests.post(self.es_url,
                                                         auth=awsauth,
                                                         json=jsn,
                                                         headers={'Content-Type': 'application/json'},
                                                         timeout=Parser.__Timeout)
                                # Raises an exception if we didn't get back a
                                # 200 code
                                response.raise_for_status()
                            except requests.exceptions.RequestException as e:
                                logging.exception('Unable to save the DMARC aggregate report to Elasticsearch')
                                success = False
                    else:
                        logging.error('RUA payload failed schema validation')
                        self.pp_validation_error(tree)
                        success = False
                else:
                    logging.error('RUA payload failed XML parsing')
                    success = False

        return success

    @staticmethod
    def listify(x):
        """If x is a list then just return it.  If x is a dict then
        return a list with x as the sole item.

        Parameters
        ----------
        x : list, dict
            The list or dict to be listified.

        Returns
        -------
        list: x if x is a list.  If x is a dict then returns a list
        with x as the sole item.
        """
        retVal = x
        if isinstance(x, dict):
            retVal = [x]

        return retVal


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

    Returns
    -------
    bool: True if the payload was parsed successfully and False
    otherwise.
    """
    logging.info('Processing: ' + obj.key)
    body = obj.get()['Body'].read()
    message = email.message_from_bytes(body)
    parsingSuccessful = parser.process_message(message)
    if not parsingSuccessful:
        logging.warning('Parsing NOT completely successful for S3 object with '
                        'key {}'.format(obj.key))

    if delete:
        if parsingSuccessful:
            logging.debug('Deleting S3 object with key {}'.format(obj.key))
            obj.delete()
        else:
            logging.warning('Not deleting S3 object with key {} because parsing '
                            'was not completely successful'.format(obj.key))

    return parsingSuccessful


def do_it(schema, s3_bucket, s3_keys=None, domains=None,
          reports=None, elasticsearch=None, es_region=None,
          dmarcian_token=None, delete=False):
    """Process one or more email messages retrieved from an S3 bucket.

    Each (possibly multipart) email message should contain one or more
    DMARC aggregate reports.

    Parameters
    ----------
    schema : str
        The path to the XSD file against which the DMARC aggregate
        reports are to be be verified.

    s3_bucket : str
        The AWS S3 bucket containing the DMARC aggregate reports.

    s3-keys : str
        A comma-separated list of DMARC aggregate report keys.  If not
        None then only the specified DMARC aggregate reports will be
        processed.  Otherwise all reports in the AWS S3 bucket will be
        processed.

    domains : str
        A file to which to save a list of all domains for which DMARC
        aggregate reports were received.  If None then no such file
        will be created.

    reports : str
        A directory to which to write files containing DMARC aggregate
        report contents.  If None then no such files will be created.

    elasticsearch : str
        A URL corresponding to an AWS Elasticsearch instance,
        including the index where the DMARC aggregate reports should
        be written.  If None then data will not be saved to
        Elasticsearch.

    es_region : str
        The AWS region where the Elasticsearch instance is located.
        Can be None if Elasticsearch is not being used.

    dmarcian_token : str
        The Dmarcian API token.  If not None then the Dmarcian API
        will be queried to determine what commercial mail-sending
        organization (if any) is associated with the IP in the
        aggregate report.

    delete : bool
        If present then the reports will be deleted after processing.

    Returns
    -------
    dict : A dict whose keys are the S3 object keys and whose values
    are a boolean value indicating whether parsing was successful for
    that key.
    """
    returnVal = {}
    parser = Parser(schema, domains, reports, elasticsearch,
                    es_region, dmarcian_token)
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(s3_bucket)
    if s3_keys:
        # The user specified the keys
        for key in s3_keys.split(','):
            success = process(bucket.Object(key.strip()), parser, delete)
            returnVal[key] = success
    else:
        # The user didn't specify the keys so iterate over all the keys in the
        # bucket
        for obj in bucket.objects.all():
            success = process(obj, parser, delete)
            returnVal[key] = success

    return returnVal


def main():
    # Parse command line arguments
    args = docopt.docopt(__doc__, version=__version__)

    # Set up logging
    log_level = logging.WARNING
    if args['--log-level']:
        log_level = args['--log-level']
    try:
        logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s',
                            level=log_level.upper())
    except ValueError as e:
        logging.critical('"{}" is not a valid logging level.  Possible values '
                         'are debug, info, warn, and error.'.format(log_level))
        sys.exit(1)

    # Handle some command line arguments
    delete = False
    if args['--delete']:
        delete = True

    token = None
    if args['--dmarcian-token']:
        with open(args['--dmarcian-token'], 'r') as token_file:
            token = token_file.read().strip()

    # Get down to business
    do_it(args['--schema'], args['--s3-bucket'], args['--s3-keys'],
          args['--domains'], args['--reports'],
          args['--elasticsearch'], args['--es-region'], token, delete)

    # Stop logging and clean up
    logging.shutdown()


if __name__ == '__main__':
    main()
