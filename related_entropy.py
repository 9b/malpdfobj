import math
import json
import os
import optparse

def H(data):
        entropy = 0
        for x in range(256):
                p_x = float(data.count(chr(x)))/len(data)
                if p_x > 0:
                        entropy += - p_x*math.log(p_x, 2)
        return entropy

def bytes_from_file(filename, chunksize=32):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            if chunk:
                data = str(H(chunk)) + ',' + str(f.tell())
                yield data
            else:
                break

def entropy_offsets(f):
        total = []
        for b in bytes_from_file(f):
                total.append(b)
        return total

def compare_ent(f1, f2, t):
        count = 0
        x = 0
        total = []
        for pair in f1:
                data = pair.split(',')
                ent = data[0].rstrip()
                off = data[1].rstrip()

                if x < len(f2):
                        data = f2[x].split(',')
                        ent_ = data[0].rstrip()
                        off_ = data[1].rstrip()

                        if count <= 5:
                                if ent == ent_:
					count +=1

                                value = abs(float(ent) - float(ent_))                       
                                if float(value) < float(t):
                                        count += 1
                                else:
                                        count = 0

                        else:
                                count = 0
                                offset_pair = off + "," + off_
                                total.append(offset_pair)
                x += 1

        return total

def shot_caller(file):
	res = entropy_offsets(file)
	files = []
	results = []
	dir = '/home/bsdixon/PDFs/files/'
	dirlist = os.listdir(dir)
	for fname in dirlist:
		if fname != "." or fname != "..":
			files.append(dir + fname)
	files.sort()
        
	for file in files:
		res2 = entropy_offsets(file)
		match_points = compare_ent(res, res2, .2)
		if len(match_points) > 5:
			preobj = { 'file' : file, 'offsets' : match_points }
			results.append(preobj)
			
	return results
