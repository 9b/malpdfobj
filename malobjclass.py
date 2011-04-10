import simplejson as json

__author__ = "Brandon Dixon"
__email__ = "brandon@9bplus.com"

class jPdf():
	def __init__(self, raw_json):
		self._scores = None
		self._primary_score = None
		self._secondary_score = None
		self._total_score = None

		self._hash_data = None
		self._file_hashes = None
		self._file_md5 = None
		self._file_sha1 = None
		self._file_sha256 = None

		self._contents = None
		self._objs = []

		self._scans = None
		self._virustotal_report = None
		self._virustotal_last_scan = None
		self._virustotal_permalink = None
		self._virustotal_scan_results = None

		self._structure = None
		self._components = []
		self._keywords = []
		self._header = None
		self._filesize = None
		self._non_stream_entropy = None
		self._stream_entropy = None
	
		#go forth and parse
		self.dump_data(raw_json)

	def dump_data(self, json):
		#top level
		self._scores = self.shallow_diver(json,"scores")
		self._hash_data = self.shallow_diver(json,"hash_data")
		self._file_hashes = self.shallow_diver(self._hash_data,"file")
		self._contents = self.shallow_diver(json,"contents")
		self._objects = self.shallow_diver(self._contents,"objects")
		self._object = self.shallow_diver(self._objects,"object")
		self._scans = self.shallow_diver(json,"scans")
		self._virustotal_report = self.shallow_diver(self._scans,"report")
		self._virustotal_results = self.shallow_diver(self._virustotal_report,"results")
		self._structure = self.shallow_diver(json,"structure")
		self._components_d = self.shallow_diver(self._structure,"components")
		self._component = self.shallow_diver(self._components_d,"component")
		self._keywords_d = self.shallow_diver(self._structure,"keywords")
		self._keyword = self.shallow_diver(self._keywords_d,"keyword")

		#scores
		self.set_scores(self._scores)
		self.set_primary_score(self._scores.get("primary"))
		self.set_secondary_score(self._scores.get("secondary"))
		self.set_total_score(self._scores.get("total"))

		#hash_data
		self.set_hash_data(self._hash_data)
		self.set_file_hashes(self._file_hashes)
		self.set_file_md5(self._file_hashes.get("md5"))
		self.set_file_sha1(self._file_hashes.get("sha1"))
		self.set_file_sha256(self._file_hashes.get("sha256"))

		#contents
		self.set_contents(self._contents)
		self.process_objects(self._object)
		self.set_objs(self._objs)

		#scans
		self.set_scans(self._scans)
		self.set_virustotal_report(self._virustotal_report)
		self.set_virustotal_last_scan(self._virustotal_report.get("last_scan"))
		self.set_virustotal_permalink(self._virustotal_report.get("permalink"))
		self.set_virustotal_scan_results(self._virustotal_results.get("scanners"))

		#structure
		self.set_structure(self._structure)
		self.set_header(self._structure.get("header"))
		self.set_filesize(self._structure.get("filesize"))
		self.set_non_stream_entropy(self._structure.get("nonStreamEntropy"))
		self.set_stream_entropy(self._structure.get("streamEntropy"))
		self.process_named_functions(self._component,"components")
		self.process_named_functions(self._keyword,"keywords")

	def process_objects(self,json):
		for obj in json:
			iobj = jObj(obj)
			self._objs.append(iobj)

	def process_named_functions(self,json,type):
		for named_function in json:
			inamed_function = jNamedFunctions(named_function)
			if type == "components":
				self._components.append(inamed_function)
			else:
				self._keywords.append(inamed_function)

	#setters
	def set_scores(self,scores):
		self._scores = scores
	def set_primary_score(self,primary):
		self._primary_score = primary
	def set_secondary_score(self,secondary):
		self._secondary_score = secondary
	def set_total_score(self,total):
		self._total_score = total

	def set_hash_data(self,hash_data):
		self._hash_data = hash_data
	def set_file_hashes(self,file_hashes):
		self._file_hashes = file_hashes
	def set_file_md5(self,file_md5):
		self._file_md5 = file_md5
        def set_file_sha1(self,file_sha1):
                self._file_sha1 = file_sha1
        def set_file_sha256(self,file_sha256):
                self._file_sha256 = file_sha256

	def set_contents(self,contents):
		self._contents = contents
	def set_objs(self,objs):
		self._objs = objs

	def set_scans(self,scans):
		self._scans = scans
	def set_virustotal_report(self,virustotal_report):
		self._virustotal_report = virustotal_report
	def set_virustotal_last_scan(self,virustotal_last_scan):
		self._virustotal_last_scan = virustotal_last_scan
	def set_virustotal_permalink(self,virustotal_permalink):
		self._virustotal_permalink = virustotal_permalink
	def set_virustotal_scan_results(self,virustotal_scan_results):
		self._virustotal_scan_results = virustotal_scan_results

	def set_structure(self,structure):
		self._structure = structure
	def set_components(self,components):
		self._components = components
	def set_keywords(self,keywords):
		self._keywords = keywords
	def set_header(self,header):
		self._header = header
	def set_filesize(self,filesize):
		self._filesize = filesize
	def set_non_stream_entropy(self,non_stream_entropy):
		self._non_stream_entropy = non_stream_entropy
	def set_stream_entropy(self,stream_entropy):
		self._stream_entropy = stream_entropy

	#getters
	def get_scores(self):
		return self._scores
	def get_primary_score(self):
		return self._primary_score
	def get_secondary_score(self):
		return self._secondary_score
	def get_total_score(self):
		return self._total_score

	def get_hash_data(self):
		return self._hash_data
	def get_file_hashes(self):
		return self._file_hashes
	def get_file_md5(self):
		return self._file_md5
	def get_file_sha1(self):
		return self._file_sha1
	def get_file_sha256(self):
		return self._file_sha256

	def get_contents(self):
		return self._contents
	def get_objs(self):
		return self._objs

	def get_scans(self):
		return self._scans
	def get_virustotal_report(self):
		return self._virustotal_report
	def get_virustotal_last_scan(self):
		return self._virustotal_last_scan
	def get_virustotal_permalink(self):
		return self._virustotal_permalink
	def get_virustotal_scan_results(self):
		return self._virustotal_scan_results

	def get_structure(self):
		return self._structure
	def get_components(self):
		return self._components
	def get_keywords(self):
		return self._keywords
	def get_header(self):
		return self._header
	def get_filesize(self):
		return self._filesize
	def get_non_stream_entropy(self):
		return self._non_stream_entropy
	def get_stream_entropy(self):
		return self._stream_entropy

	#properties
	scores = property(get_scores,set_scores)
	primary_score = property(get_primary_score,set_primary_score)
	secondary_score = property(get_secondary_score,set_secondary_score)
	total_score = property(get_total_score,set_total_score)

	hash_data = property(get_hash_data,set_hash_data)
	file_hashes = property(get_file_hashes,set_file_hashes)
	file_md5 = property(get_file_md5,set_file_md5)
	file_sha1 = property(get_file_sha1,set_file_sha1)
	file_sha256 = property(get_file_sha256,set_file_sha256)

	contents = property(get_contents,set_contents)
	objs = property(get_objs,set_objs)

	scans = property(get_scans,set_scans)
	virustotal_report = property(get_virustotal_report,set_virustotal_report)
	virustotal_last_scan = property(get_virustotal_last_scan,set_virustotal_last_scan)
	virustotal_permalink = property(get_virustotal_permalink,set_virustotal_permalink)
	virustotal_scan_results = property(get_virustotal_scan_results,set_virustotal_scan_results)

	structure = property(get_structure,set_structure)
	components = property(get_components,set_components)
	keywords = property(get_keywords,set_keywords)
	header = property(get_header,set_header)
	filesize = property(get_filesize,set_filesize)
	non_stream_entropy = property(get_non_stream_entropy,set_non_stream_entropy)
	stream_entropy = property(get_stream_entropy,set_stream_entropy)

	#Grab objects at the top level or second level
	def shallow_diver(self,json,shell):
        	for key, value in json.iteritems():
	               	if shell == key:
                        	data = json.get(shell)
	                        break
        	        else:
                	        if shell in value:
                        	        data = json.get(key)
                                	data = self.shallow_diver(data,shell)

	        return data


class jObj():
	def __init__(self,raw_json):
		self._objs = []
		self._decoded = None
		self._encoded = None
		self._hex = None
		self._id = None
		self._length = None
		self._hash = None
		self._suspicious = None
		self._version = None

		self.dump_data(raw_json)

	def dump_data(self,json):
		self._decoded = json.get("decoded")
		self._encoded = json.get("encoded")
		self._hex = json.get("hex")
		self._id = json.get("id")
		self._length = json.get("length")
		self._hash = json.get("md5")
		self._suspicious = json.get("suspicious")
		self._version = json.get("version")

		self.set_decoded(self._decoded)
		self.set_encoded(self._encoded)
		self.set_hex(self._hex)
		self.set_id(self._id)
		self.set_length(self._length)
		self.set_hash(self._hash)
		self.set_suspicious(self._suspicious)
		self.set_version(self._version)

	def set_decoded(self,decoded):
		self._decoded = decoded
	def set_encoded(self,encoded):
		self._encoded = encoded
	def set_hex(self,hex):
		self._hex = hex
	def set_id(self,id):
		self._id = id
	def set_length(self,length):
		self._length = length
	def set_hash(self,hash):
		self._hash = hash 
	def set_suspicious(self,suspicious):
		self._suspicious = suspicious
	def set_version(self,version):
		self._version = version
	
	def get_decoded(self):
		return self._decoded
	def get_encoded(self):
		return self._encoded
	def get_hex(self):
		return self._hex
	def get_id(self):
		return self._id
	def get_length(self):
		return self._length
	def get_hash(self):
		return self._hash
	def get_suspicious(self):
		return self._suspicious
	def get_version(self):
		return self._version

	decoded = property(get_decoded,set_decoded)
	encoded = property(get_encoded,set_encoded)
	hex = property(get_hex,set_hex)
	id = property(get_id,set_id)
	length = property(get_length,set_length)
	hash = property(get_hash,set_hash)
	suspicious = property(get_suspicious,set_suspicious)
	version = property(get_version,set_version)
			
class jNamedFunctions():
	def __init__(self,raw_json):
		self._count = None
		self._hex_count = None
		self._name = None

		self.dump_data(raw_json)		
	
	def dump_data(self,json):
		self._count = json.get("count")
		self._hex_count = json.get("hexcodecount")
		self._name = json.get("name")

		self.set_count(self._count)
		self.set_hex_count(self._hex_count)
		self.set_name(self._name)

	def set_count(self,count):
		self._count = count
	def set_hex_count(self,hex_count):
		self._hex_count = hex_count
	def set_name(self,name):
		self._name = name

	def get_count(self):
		return self._count
	def get_hex_count(self):
		return self._hex_count
	def get_name(self):
		return self._name

	count = property(get_count,set_count)
	hex_count = property(get_hex_count,set_hex_count)
	name = property(get_name,set_name)
