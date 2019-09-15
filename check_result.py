

import json
import sys



def read_file(file_path) :
	file = open(file_path)
	data = file.read()

	file.close()

	return data


if __name__ == '__main__' :
	if not 2 == len(sys.argv) :
		print 'Using :'
		print 'python check_result.py file_path'

		exit()

	json_data = read_file(sys.argv[1])
	json_data = json.loads(json_data)
	contract_list = json_data.keys()
	contract_count = len(contract_list)
	type_count_static = {}
	type_static = {}

	for contract_index in contract_list :
		contract_file_name = contract_index
		contract_type = json_data[contract_index]

		if not contract_type in type_count_static.keys() :
			type_count_static[contract_type] = 0

		if not contract_type in type_static.keys() :
			type_static[contract_type] = []

		type_count_static[contract_type] += 1

		type_static[contract_type].append(contract_file_name)

	print 'Checking Analayis :'
	print 'All Contract Count =',len(contract_list)

	for type_index in type_count_static.keys() :
		print 'Type ',type_index,'Count:',type_count_static[type_index]

	print 'Contract File ...'

	for type_index in type_static.keys() :
		print 'Type ',type_index

		contract_file_list = type_static[type_index]

		for contract_file_index in contract_file_list :
			print contract_file_index

