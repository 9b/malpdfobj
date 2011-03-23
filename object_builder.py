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
import parser_contents2json
import pdfid_mod
import related_entropy
import hashlib
import hash_maker
import optparse
import pymongo
import MySQLdb
import traceback
from pymongo import Connection

def get_vt_obj(file):
	key = 'YOUR_API_KEY'
	url = "https://www.virustotal.com/api/get_file_report.json"
	parameters = {"resource": file, "key": key}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	vtobj = response.read()

	preprocess = json.loads(vtobj)
	report = preprocess.get("report")
	permalink = preprocess.get("permalink")
	result = preprocess.get("result")

	if int(result) == 1:
		scanners = []
		last_scan = report[0]
		for k, v in report[1].iteritems():
			scanner = { 'antivirus' : k, 'signature' : v }
			scanners.append(scanner)

		vtobj = { 'report' : { 'last_scan':last_scan, 'permalink':permalink, 'results' : { 'scanners' : scanners } } }
	else:
		vtobj = { 'report' : { 'results': {'scanners' : [] } } }

	return json.dumps(vtobj)
	
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
	#objs = json.loads(get_object_details(file)) #decode because data needs to be re-encoded
	hashes = hash_maker.get_hash_object(file)
	data = { 'file': hashes }
	return json.dumps(data)
	
def get_contents_obj(file):
	objcontents = json.loads(parser_contents2json.contents(file))
	data = { 'objects': objcontents }
	return json.dumps(data)	

def get_related_files(file):
	related_results = related_entropy.shot_caller(file)
	return json.dumps(related_results)
	
def connect_to_mongo(host, port, database, collection):
	connection = Connection(host, port)
	db = connection[database]
	collection = db[collection]
	return collection
	
def connect_database(host, user, password, database): #9b+
        try:
                conn = MySQLdb.connect (host, user, password, database)
                return conn
        except MySQLdb.Error, e:
                print "Error %d: %s" % (e.args[0], e.args[1])
                sys.exit(1)
        
def kill_database_connection(conn): #9b+
        conn.commit()
        conn.close()

def build_obj(file, dir=''):

	if dir != '':
		file = dir + file
	
	vt_hash = hash_maker.get_hash_data(file, "md5")
	
	#get the json decoded data
	fhashes = json.loads(get_hash_obj(file))
	fstructure = json.loads(get_structure(file))
	fscore = json.loads(get_scores(file))
	fvt = json.loads(get_vt_obj(vt_hash))
	fcontents = json.loads(get_contents_obj(file))
#	frelated = json.loads(get_related_files(file))	
	frelated = "null"
	
	#build the object and then re-encode
	fobj = { "hash_data": fhashes, "structure": fstructure, "scores" : fscore, "scans": { "virustotal": fvt, "wepawet": "null" }, "contents" : fcontents, 'related' : frelated }
	return json.dumps(fobj)
	
def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', default='', type='string', help='file to build an object from')
    oParser.add_option('-d', '--dir', default='', type='string', help='dir to build an object from')
    oParser.add_option('-m', '--mongo', action='store_true', default=False, help='dump to a mongodb database')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose outpout')
    oParser.add_option('-l', '--log', action='store_true', default=False, help='log errors to file')
    (options, args) = oParser.parse_args()

    if options.log:
	log = open("error_log",'w')    

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
                                hash = hash_maker.get_hash_data(options.dir + file, "md5")
                                pres = con.find({"hash_data.file.md5":hash}).count()
                                if pres != 1:
                                        output = build_obj(file, options.dir)
                                        if options.mongo:
                                                try:
                                                        con.insert(json.loads(output))
                                                        if options.verbose:
                                                                print file + " inserted"
                                                except:
                                                        print "Something went wrong with" + file
                                                        traceback.print_exc()
                                                        if options.log:
                                                                log.write("ERROR: " + file + "\n")
                                        count += 1
                if options.log:
                        log.close()

    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()
