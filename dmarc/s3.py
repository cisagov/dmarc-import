#!/usr/bin/env python3
import logging
import traceback
import boto3
import email
import gzip
import io
import zipfile
from lxml import etree
import re


'''
Processes email which (tries to) follow RFC7489:
https://tools.ietf.org/html/rfc7489#section-7.2.1.1
'''

BUCKET_NAME = 'cyhy-dmarc-report-emails'
SCHEMA = etree.XMLSchema(file='/usr/src/boat/dmarc/rua_mod.xsd') #TODO
PARSER = etree.XMLParser(schema=SCHEMA) #TODO

def setup_logging(level=logging.INFO, console=False, filename=None):
    LOGGER_FORMAT = '%(asctime)-15s %(levelname)s %(name)s - %(message)s'
    formatter = logging.Formatter(LOGGER_FORMAT)
    formatter.converter = time.gmtime # log times in UTC
    root = logging.getLogger()
    root.setLevel(level)
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.addFilter(LogFilter())
        root.addHandler(console_handler)
    if filename:
        file_handler = RotatingFileHandler(filename, maxBytes=pow(1024,2) * 128, backupCount=9)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(LogFilter())
        root.addHandler(file_handler)
    return root

def pp(tree):
    print(etree.tostring(tree, pretty_print=True).decode())

def pp_validation_error(tree):
    print(SCHEMA.error_log)
    line_num = 2 # Dunno, it lines up with error messages
    for line in etree.tostring(tree).decode().splitlines():
        print('%d\t%s' % (line_num, line))
        line_num += 1

def pp_parse_error(payload, e):
    print(e.error_log)
    line_num = 1
    for line in payload.splitlines():
        print('%d\t%s' % (line_num, line))
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
    print('\t' + content_type + '\t size:' + str(len(payload)))
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
        print('RUA payload FAILED xml parsing')
        return None

    valid = SCHEMA.validate(tree)
    if valid:
        print('RUA payload passed schema validation')
    else:
        print('RUA payload FAILED schema validation')
        pp_validation_error(tree)
    return tree

def process_message(message):
    if message.is_multipart():
        # loop through message parts
        for part in message.get_payload():
            xml = process_payload(part.get_content_type(), part.get_payload(decode=True))
    else: # not multipart
        xml = process_payload(message.get_content_type(), message.get_payload(decode=True))
    return xml

def main():
    s3 = boto3.resource('s3')
    b = s3.Bucket(BUCKET_NAME)
    domains = set()
    keys = [i.key for i in b.objects.all()]
    #keys = [#'9lnmq3vep46ud66g7361o2otm18gri276hpu3no1', # GOOD
    #       'dgjkhkmomb3iigunebqbbmpb1rnr76cfojnnqgo1'] # BAD
    print('Processing %d emails' % len(keys))
    for key in keys:
        print('Processing: ' + key)
        body = b.Object(key).get()['Body'].read()
        message = email.message_from_bytes(body)
        tree = process_message(message)
        if tree is not None:
            d = tree.find('policy_published').find('domain').text
            print(d)
            domains.add(d)
    for d in sorted(list(domains)):
        print(d)
    #import IPython; IPython.embed() #<<< BREAKPOINT >>>



if __name__ == '__main__':
    main()
