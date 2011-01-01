__description__ = 'Builds JSON object representing a malicious PDF'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/01/01'

import simplejson as json
import urllib
import urllib2
import os
import time
import parser_hash2json
import pdfid_mod
import hashlib
import hash_maker
import optparse

def get_vt_obj(file):
	url = "https://www.virustotal.com/api/get_file_report.json"
	parameters = {"resource": file, "key": "a2fec6adeea43e021c3439fc39986b161a06d976f2a534f3cd5fb4333ce2de8f"}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	vtobj = response.read()
	return vtobj
	
def get_structure(file):
	structureobj = pdfid_mod.PDFiD2JSON(pdfid_mod.PDFiD(file, True, True, False, True), True)
	return structureobj

def get_object_details(file):
	objdetails = parser_hash2json.conversion(file)
	return objdetails

def get_hash_obj(file):
	objs = json.loads(get_object_details(file)) #decode because data needs to be re-encoded
	hashes = hash_maker.get_hash_object(file)
	data = { 'hashes': { 'file': hashes, 'objects': objs} }
	return json.dumps(data)
	
def build_obj(file):
	
	#split file aspects for VirusTotal
	data = file.split('/')
	vt_file = data[5]
	data = vt_file.split('.')
	vt_hash = data[0]

	#get the json decoded data
	fhashes = json.loads(get_hash_obj(file))
	fstructure = json.loads(get_structure(file))
	fvt = json.loads(get_vt_obj(vt_hash))
	
	#build the object and then re-encode
	fobj = { "hash_data": fhashes, "structure": fstructure, "scans": { "virustotal": fvt, "wepawet": "null" } }
	return json.dumps(fobj)
	
def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', default='', type='string', help='file to build abn object from')
    (options, args) = oParser.parse_args()

	#file assumes the following: absolute path, filename is "hash.pdf.vir"
    if options.file:
		print build_obj(options.file)
    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()
