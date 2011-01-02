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
import pymongo
from pymongo import Connection

def get_vt_obj(file):
	key = ''
	url = "https://www.virustotal.com/api/get_file_report.json"
	parameters = {"resource": file, "key": key}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	vtobj = response.read()
	return vtobj
	
def get_structure(file):
	structureobj = pdfid_mod.PDFiD2JSON(pdfid_mod.PDFiD(file, True, True, False, True), True)
	return structureobj
	
def get_scores(file):
	scoreobj = pdfid_mod.Score2JSON(pdfid_mod.PDFiD(file, True, True, False, True))
	return scoreobj

def get_object_details(file):
	objdetails = parser_hash2json.conversion(file)
	return objdetails

def get_hash_obj(file):
	objs = json.loads(get_object_details(file)) #decode because data needs to be re-encoded
	hashes = hash_maker.get_hash_object(file)
	data = { 'hashes': { 'file': hashes, 'objects': objs} }
	return json.dumps(data)
	
def connect_to_mongo(host, port, database, collection):
	connection = Connection(host, port)
	db = connection[database]
	collection = db[collection]
	return collection
	
def build_obj(file, dir=''):

	if dir != '':
		file = dir + file
	
	vt_hash = hash_maker.get_hash_data(file, "md5")
	
	#get the json decoded data
	fhashes = json.loads(get_hash_obj(file))
	fstructure = json.loads(get_structure(file))
	fscore = json.loads(get_scores(file))
	fvt = json.loads(get_vt_obj(vt_hash))
	
	#build the object and then re-encode
	fobj = { "hash_data": fhashes, "structure": fstructure, "scores" : fscore, "scans": { "virustotal": fvt, "wepawet": "null" } }
	return json.dumps(fobj)
	
def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', default='', type='string', help='file to build an object from')
    oParser.add_option('-d', '--dir', default='', type='string', help='dir to build an object from')
    oParser.add_option('-m', '--mongo', action='store_true', default=False, help='dump to a mongodb database')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose outpout')
    (options, args) = oParser.parse_args()
    
    if options.mongo:
    	con = connect_to_mongo("localhost", 27017, "pdfs", "malware")

	#file assumes the following: absolute path, filename is "hash.pdf.vir"
    if options.file:
    	output = build_obj(options.file)
    	if options.mongo:
			con.insert(json.loads(output))
        if options.verbose:
			print output
    elif options.dir:
		files = []
		dirlist = os.listdir(options.dir)
		for fname in dirlist:
			files.append(fname)
		files.sort()
		count = 0

		for file in files:
			if count == 20:
				if options.verbose:
					print "Sleeping for 5 minutes"
				time.sleep(300)
				count = 0
			else:
				output = build_obj(file, options.dir)
				if options.mongo:
					con.insert(json.loads(output))
					if options.verbose:
						print file + " inserted"
				if options.verbose:
					print build_obj(file, options.dir)
				count += 1
    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()
