
import time
import threading

from web3 import Web3


def binary_to_hex_string(binary_contract_code) :
	hex_string = ''

	for index in binary_contract_code :
		byte_hex_number = str(hex(index))
		hex_string += byte_hex_number[ 2 : ]

	return hex_string

def get_contract_code(contract_address) :
	eth_connector = Web3(Web3.HTTPProvider('http://node1.web3api.com'))

	return binary_to_hex_string(eth_connector.eth.getCode(contract_address))

def get_current_blocknumber() :
	eth_connector = Web3(Web3.HTTPProvider('http://node1.web3api.com'))

	return eth_connector.eth.blockNumber

def get_block(block_height) :
	eth_connector = Web3(Web3.HTTPProvider('http://node1.web3api.com'))

	return eth_connector.eth.getBlock(block_height)

def get_transation(transation_hash) :
	eth_connector = Web3(Web3.HTTPProvider('http://node1.web3api.com'))

	return eth_connector.eth.getTransaction(transation_hash)

def get_contract_create_from_blockdata(block_height) :
	block_data = get_block(block_height)
	contract_result = {}

	for transation_id in block_data['transactions'] :
		transaction_data = get_transation(transation_id)

		if None == transaction_data['creates'] :
			continue

		contract_result[transaction_data['creates']] = transaction_data['input'][ 2 : ]

	return contract_result


TIME_INTERVAL = 5.0

if __name__ == '__main__' :
	last_block_height = 0

	while True :
		current_block_height = get_current_blocknumber()
		time_tick = time.time()

		if current_block_height > last_block_height :
			print('new blockheight:',current_block_height)
			print(get_contract_create_from_blockdata(current_block_height))

			current_block_height = last_block_height
		else :
			print('no found new block ..')

		outdate_time = time.time() - time_tick

		if outdate_time > 0 :
			time.sleep(outdate_time)


	#block_height = get_current_blocknumber()
	#block_data = get_block(block_height)

	#print(block_height)
	#print(block_data)

	#for transation_id in block_data['transactions'] :
	#	print('>>>>' ,transation_id)


	#print(get_contract_code('0xce0b7fc318A2b29193c536388d8BD8802c33deE7'))




