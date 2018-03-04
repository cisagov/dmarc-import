#!/usr/bin/env python3

"""dmarc-import: A tool for parsing DMARC aggregate reports.  The
expected format of these aggregate reports is described in RFC7489
(https://tools.ietf.org/html/rfc7489#section-7.2.1.1).

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
"""

import binascii
import datetime
import email
import gzip
import io
import logging
import re
import traceback
import zipfile

import boto3
import docopt
from lxml import etree

from dmarc import __version__


BUCKET_NAME = 'cyhy-dmarc-report-emails'
SCHEMA = etree.XMLSchema(file='/usr/src/boat/dmarc/rua_mod.xsd') #TODO
PARSER = etree.XMLParser(schema=SCHEMA) #TODO

def pp(tree):
    print(etree.tostring(tree, pretty_print=True).decode())

def pp_validation_error(tree):
    logging.error(SCHEMA.error_log)
    line_num = 2 # Dunno, it lines up with error messages
    for line in etree.tostring(tree).decode().splitlines():
        logging.error('%d\t%s' % (line_num, line))
        line_num += 1

def pp_parse_error(payload, e):
    logging.error(e.error_log)
    line_num = 1
    for line in payload.splitlines():
        logging.error('%d\t%s' % (line_num, line))
        line_num += 1

def patch_xml(payload):
    '''The rua schema needs some fixing'''
    patched = re.sub(b'<feedback.*?>', b'<provider:feedback xmlns:provider="http://dmarc.org/dmarc-xml/0.1">', payload)
    patched = re.sub(b'</feedback>', b'</provider:feedback>', patched)
    return patched

def parse_payload(payload):
    try:
        tree = etree.fromstring(payload)
    except etree.XMLSyntaxError as e:
        pp_parse_error(payload, e)
        return None
    return tree

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
        pass #TODO: log
    else:
        return None #TODO: log
    return payload

def process_payload(content_type, payload):
    if payload == None:
        return
    payload = decode_payload(content_type, payload)
    if payload == None:
        return
    patched = patch_xml(payload)
    tree = parse_payload(patched)
    if tree is None:
        logging.error('RUA payload FAILED xml parsing')
        return None

    valid = SCHEMA.validate(tree)
    if valid:
        logging.debug('RUA payload passed schema validation')
    else:
        logging.error('RUA payload FAILED schema validation')
        pp_validation_error(tree)
    return tree

def process_message(message):
    if message.is_multipart():
        # loop through message parts
        for part in message.get_payload():
            try:
                xml = process_payload(part.get_content_type(), part.get_payload(decode=True))
            except (binascii.Error, AssertionError) as e:
                logging.error('Caught an exception', e)
    else: # not multipart
        try:
            xml = process_payload(message.get_content_type(), message.get_payload(decode=True))
        except (binascii.Error, AssertionError) as e:
                logging.error('Caught an exception', e)
    return xml

def main():
    # Parse command line arguments
    args = docopt.docopt(__doc__, version=__version__)

    # Set up logging
    log_level = logging.WARNING
    if args['--debug']:
        log_level = logging.DEBUG
    logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s', level=log_level)

    s3 = boto3.resource('s3')
    bucket = s3.Bucket(args['--s3-bucket'])
    domains = set()
    for obj in bucket.objects.all():
        key = obj.key
        logging.info('Processing: ' + key)
        body = bucket.Object(key).get()['Body'].read()
        message = email.message_from_bytes(body)
        tree = process_message(message)
        if tree is not None:
            domain = tree.find('policy_published').find('domain').text
            start = tree.find('report_metadata').find('date_range').find('begin').text
            end = tree.find('report_metadata').find('date_range').find('end').text
            domains.add(domain)

            logging.info('Received a report for {} that spans {} through {}'.format(domain, datetime.datetime.utcfromtimestamp(int(start)), datetime.datetime.utcfromtimestamp(int(end))))

    for d in sorted(list(domains)):
        print(d)

    # Stop logging and clean up
    logging.shutdown()


if __name__ == '__main__':
    main()
