
import json
import requests
import os
import sys
import time

from bs4 import BeautifulSoup

from web3 import Web3


BASE_URL = 'https://etherscan.io/contractsVerified/%d?ps=100'
CONTRACT_URL = 'https://etherscan.io/address/%s#code'


def binary_to_hex_string(binary_contract_code) :
	hex_string = ''

	for index in binary_contract_code :
		byte_hex_number = str(hex(index))
		hex_string += byte_hex_number[ 2 : ]

	return hex_string

def get_contract_code_from_getCode(contract_address) :
	eth_connector = Web3(Web3.HTTPProvider('http://node1.web3api.com'))

	return binary_to_hex_string(eth_connector.eth.getCode(contract_address))

def get_contract_code_from_ethscan(contract_address) :
	return get_code(contract_address)

def get_page(page_index) :
	url = BASE_URL % page_index
	responed = requests.get(url)
	html = BeautifulSoup(responed.text,'lxml')
	element_list = html.find_all('tr')
	contract_list = {}

	if len(element_list) <= 8 :
		return False

	for index in range(1,101) :
		element_index = element_list[index]
		td_list = element_index.find_all('td')
		contract_address = td_list[0].find('a')['href']
		contract_address = contract_address[ contract_address.rfind('/') + 1 : contract_address.find('#') ]
		contract_name = td_list[1].text
		contract_balance = td_list[3].text
		contract_tx_count = int(td_list[4].text)
		contrace_date = td_list[6].text

		contract_list[contract_address] = {
			'contract_address' : contract_address ,
			'contract_name' : contract_name ,
			'contract_balance' : contract_balance ,
			'contract_tx_count' : contract_tx_count ,
			'contrace_date' : contrace_date ,
		}

	return contract_list

def get_code(contract_address) :
	url = CONTRACT_URL % contract_address
	responed = requests.get(url)
	html = BeautifulSoup(responed.text,'lxml')
	contract_code = html.find('div',attrs = {'id' : 'verifiedbytecode2'})

	if not None == contract_code :
		contract_code = contract_code.text.strip()
	else :
		return False
		contract_code = html.find('div',class_ = 'wordwrap')
		contract_code = contract_code.strip()[ 2 : ]

	return contract_code


def write_data(file_path,data) :
	file = open(file_path,'w')

	file.write(data)
	file.close()


if __name__ == '__main__' :
	if not 2 == len(sys.argv) :
		print('spider_contract_from_etherscan.py -load | -down ')
		print('  -load  update all contract address from etherscan')
		print('  -down  using contract address to down contract code ,address data from -load')

		exit()

	if '-load' == sys.argv[1] :
		all_contract_list = {}

		for page_index in range(508,600) :
			print('Page Index :',page_index)

			try :
				page_data = get_page(page_index)
			except :
				print('Except !!!')
				print(all_contract_list)
				exit()

			if not page_data :
				break

			for page_data_key_index in page_data.keys() :
				print('load contract >>',page_data_key_index)

				all_contract_list[page_data_key_index] = page_data[page_data_key_index]

				if Web3.isChecksumAddress(page_data_key_index) :
					contract_code = get_contract_code_from_ethscan(page_data_key_index)
				else :
					contract_code = get_contract_code_from_ethscan(Web3.toChecksumAddress(page_data_key_index))

				if contract_code :
					contract_file_name = '%s_%s.solc_bin' % (page_data[page_data_key_index]['contract_address'],page_data[page_data_key_index]['contract_name'])
				else :
					print('download ' + page_data_key_index + ' Error !!')

					continue

				write_data('./eth_contract/%s' % (contract_file_name),contract_code)

				time.sleep(0.5)

		print(all_contract_list)
		#write_data('./etherscan_contract_address.txt',json.dumps(all_contract_list))
	elif '-down' == sys.argv[1] :
		pass


