
import json
import subprocess
import os
import threading
import time
import Queue 

from optparse import OptionParser

from simhash import Simhash


DISTANCE_BASE_NUMBER = 0.935
SIMULATOR_VALID_VALUE_LEVEL_1 = 0.6
SIMULATOR_VALID_VALUE_LEVEL_2 = 1.0
SIMULATOR_ALERT_VALUE = 0.8


class opcode_object :

	def __init__(self,opcode,opcode_data = []) :
		self.opcode = opcode
		self.opcode_data = opcode_data

	def get_opcode(self) :
		return self.opcode

	def has_opcode_data(self) :
		if len(self.opcode_data) :
			return True
		else :
			return False

	def get_opcode_data(self,data_offset = -1) :
		if not -1 == data_offset and self.has_opcode_data() :
			return self.opcode_data[data_offset]
		else :
			return self.opcode_data

	def __str__(self) :
		opcode_data = ''

		for opcode_data_index in self.opcode_data :
			opcode_data += str(opcode_data_index) + ','

		if len(opcode_data) :
			opcode_data = opcode_data[ : -1 ]

		return '%s %s' % (self.opcode,opcode_data)

	def __repe__(self) :
		return self.__str__()

class disassmbly_object :

	def __init__(self,disassmbly_data = {}) :
		self.disassmbly_data = disassmbly_data
		self.disassmbly_address_list = self.sort_disassmbly_address()

	def get_disassmbly_data(self) :
		return self.disassmbly_data

	def get_disassmbly_data_length(self) :
		return len(self.disassmbly_data)

	def sort_disassmbly_address(self,is_reverse = False) :
		return sorted(self.disassmbly_data.keys(),reverse = is_reverse)

	def get_disassmbly_address_list(self) :
		return self.disassmbly_address_list

	def get_disassmbly_address_list_length(self) :
		return len(self.disassmbly_address_list)

	def get_disassmbly_by_index(self,index) :
		return self.disassmbly_data.values()[index]

	def get_disassmbly_by_address(self,address) :
		if not address in self.disassmbly_address_list :
			return False

		return self.disassmbly_data[address]

	def get_disassmbly_by_address_index(self,address_index) :
		if address_index >= len(self.disassmbly_address_list) :
			return False

		return self.disassmbly_data[self.disassmbly_address_list[address_index]]

	def split_bytecode(self,start_offset,end_offset = -1) :
		disassmbly_address_list = self.disassmbly_address_list

		if not start_offset in disassmbly_address_list :
			return False

		if 0 < end_offset :
			if not end_offset in disassmbly_address_list or start_offset >= end_offset:
				return False
		else :
			end_offset = disassmbly_address_list[-1]

		address_list_start_offset = disassmbly_address_list.index(start_offset)
		address_list_end_offset = disassmbly_address_list.index(end_offset)
		new_disassmbly_address_list = disassmbly_address_list[address_list_start_offset : address_list_end_offset + 1]
		new_disassmbly_data = {}

		for index in new_disassmbly_address_list :
			new_disassmbly_data[index - start_offset] = self.disassmbly_data[index]

		return disassmbly_object(new_disassmbly_data)

	def append_bytecode(self,new_disassmbly_data) :
		disassmbly_address_list = self.disassmbly_address_list

		if len(disassmbly_address_list) :
			last_offset = disassmbly_address_list[-1]
			last_opcode = self.disassmbly_data[last_offset].get_opcode()

			if last_opcode.startswith('PUSH') :  #  only PUSH will takes more byte-length,other bytecode length is 1
				push_length = int(last_opcode[ 4 : ])
				last_offset += 1 + push_length
			else :
				last_offset += 1
		else :
			last_offset = 0

		new_disassmbly_address_list = new_disassmbly_data.get_disassmbly_address_list()
		new_disassmbly_start_offset = new_disassmbly_address_list[0]

		for index in new_disassmbly_address_list :
			fix_new_disassmbly_offset = index - new_disassmbly_start_offset
			new_opcode_object = opcode_object(new_disassmbly_data.get_disassmbly_by_address(index).get_opcode(),new_disassmbly_data.get_disassmbly_by_address(index).get_opcode_data())
			self.disassmbly_data[last_offset + fix_new_disassmbly_offset] = new_opcode_object

		self.disassmbly_address_list = self.sort_disassmbly_address()

	def print_code(self) :
		disassmbly_address_list = self.get_disassmbly_address_list()

		for address_index in disassmbly_address_list :
			opcode = self.disassmbly_data[address_index]

			print address_index,':',opcode.get_opcode(),opcode.get_opcode_data()

class function_entry_object :

	def __init__(self,function_entry_list = {}) :
		self.function_entry_list = function_entry_list

	def get_all_function_entry(self) :
		return self.function_entry_list.keys()

	def get_function_entry_address(self,function_hash) :
		if not function_hash in self.function_entry_list.keys() :
			return False

		return self.function_entry_list[function_hash]

	def add_function_entry_address(self,function_hash,function_address) :
		self.function_entry_list[function_hash] = function_address

	def print_entry(self) :
		for entry_index in self.function_entry_list.keys() :
			print entry_index,' -- ',self.function_entry_list[entry_index]


def disassmbly_contract(evm_bytecode_file_path) :
	popen_object = subprocess.Popen(['./evm','disasm',evm_bytecode_file_path],stdout = subprocess.PIPE,stderr = subprocess.PIPE)
	disassmbly_data = popen_object.stdout.read()

	if  not -1 == disassmbly_data.find('invalid') or \
		not -1 == disassmbly_data.find('encoding/hex') or \
		not len(disassmbly_data.strip()) :
		return False

	disassmbly_data = disassmbly_data.split('\n')
	disassmbly_data = disassmbly_data[ 1 : ]  #  first line is source bytecode print
	format_data = {}

	for index in disassmbly_data :
		if not len(index) :
			continue

		opcode = index.split(' ')

		if 'Missing' == opcode[1] :
			continue

		opcode_address = int('0x' + opcode[0].split(':')[0],16)  #  clean the ":" in address common and convert hex number
		opcode_code = opcode[1]

		if 2 < len(opcode) :
			opcode_data = opcode[ 2 : ]
		else :
			opcode_data = []

		format_data[opcode_address] = opcode_object(opcode_code,opcode_data)

	return disassmbly_object(format_data)

def get_contract_runtime_entry(disassmbly_data) :
	disassmbly_address_list = disassmbly_data.get_disassmbly_address_list()
	disassmbly_address_list_length = disassmbly_data.get_disassmbly_address_list_length()

	for index in range(disassmbly_address_list_length) :
		if  'PUSH1' == disassmbly_data.get_disassmbly_by_address_index(index).get_opcode() and \
			'PUSH1' == disassmbly_data.get_disassmbly_by_address_index(index + 1).get_opcode() and \
			'MSTORE' == disassmbly_data.get_disassmbly_by_address_index(index + 2).get_opcode() and \
			'PUSH1' == disassmbly_data.get_disassmbly_by_address_index(index + 3).get_opcode() and '0x04' == disassmbly_data.get_disassmbly_by_address_index(index + 3).get_opcode_data(0) and \
			'CALLDATASIZE' == disassmbly_data.get_disassmbly_by_address_index(index + 4).get_opcode() :
			return disassmbly_address_list[index]
		elif 'PUSH1' == disassmbly_data.get_disassmbly_by_address_index(index).get_opcode() and \
			'PUSH1' == disassmbly_data.get_disassmbly_by_address_index(index + 1).get_opcode() and \
			'MSTORE' == disassmbly_data.get_disassmbly_by_address_index(index + 2).get_opcode() and \
			'CALLDATASIZE' == disassmbly_data.get_disassmbly_by_address_index(index + 3).get_opcode() :
			return disassmbly_address_list[index]

	return -1

def get_function_entry(disassmbly_data) :
	function_entry_flag = ['PUSH1','CALLDATALOAD']
	disassmbly_address_list = disassmbly_data.get_disassmbly_address_list()
	disassmbly_address_list_length = disassmbly_data.get_disassmbly_address_list_length()
	entry_offset = 0

	for index in range(disassmbly_address_list_length) :
		if index + 2 > disassmbly_address_list_length :
			break

		current_address = disassmbly_address_list[index]
		next_address = disassmbly_address_list[index + 1]

		if  function_entry_flag[0] == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode() and \
			function_entry_flag[1] == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode() :
			entry_offset = index + 4

			break

	if not entry_offset :
		return False

	function_entry = function_entry_object({})
	current_function_hash = 0

	for index in range(entry_offset,disassmbly_address_list_length) :
		current_address = disassmbly_address_list[index]
		current_opcode = disassmbly_data.get_disassmbly_by_address(current_address)

		if 'JUMPDEST' == current_opcode.get_opcode() :
	 		break

	 	if 'PUSH4' == current_opcode.get_opcode() and not '0xffffffff' == current_opcode.get_opcode_data(0) :
	 		current_function_hash = current_opcode.get_opcode_data(0)
	 	elif 'PUSH1' == current_opcode.get_opcode() or 'PUSH2' == current_opcode.get_opcode() :
	 		if current_function_hash :
		 		function_entry.add_function_entry_address(current_function_hash,int(current_opcode.get_opcode_data(0),16))

	 		current_function_hash = 0

	return function_entry

def get_function_code(disassmbly_data,function_entry_address,is_debug = False) :
	disassmbly_address_list = disassmbly_data.get_disassmbly_address_list()

	if not function_entry_address in disassmbly_address_list :  #  invalid entry address
		return False

	function_entry_flag = disassmbly_data.get_disassmbly_by_address(function_entry_address).get_opcode()
	disassmbly_data_length = disassmbly_data.get_disassmbly_data_length()
	disassmbly_address_list_length = disassmbly_data.get_disassmbly_address_list_length()
	function_code_object = disassmbly_object({})  #  fuck python !!!! if you dont take {} to __init__() .__init__(self,disassmbly_data) 
	#  disassmbly_data will take dirty data , its python bug !!!!

	if not 'JUMPDEST' == function_entry_flag :
		return False

	#  1. analayis function pre-check 
	
	if 'CALLVALUE' == disassmbly_data.get_disassmbly_by_address(function_entry_address + 1).get_opcode() :
		disassmbly_address_list_offset = disassmbly_address_list.index(function_entry_address + 2)
		function_pre_check_end_offset = 0
		function_argument_check_offset = 0

		for index in range(disassmbly_address_list_offset,disassmbly_address_list_length) :
			current_address = disassmbly_address_list[index]

			if index + 1 == disassmbly_address_list_length :
				break

			next_address = disassmbly_address_list[index + 1]

			if ('PUSH1' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode() or 'PUSH2' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode()) and \
				'JUMPI' == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode() :
				function_argument_check_offset = int(disassmbly_data.get_disassmbly_by_address(current_address).get_opcode_data(0),16)

			if 'JUMPDEST' == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode() :
				function_pre_check_end_offset = current_address

				break

		function_pre_check_code = disassmbly_data.split_bytecode(function_entry_address,function_pre_check_end_offset)

		if not function_argument_check_offset :
			#print '???'  ##### ?????
			return False

		if not 'JUMPDEST' == disassmbly_data.get_disassmbly_by_address(function_argument_check_offset).get_opcode() :
			return False

		disassmbly_address_list_offset = disassmbly_address_list.index(function_argument_check_offset)

		function_code_object.append_bytecode(function_pre_check_code)
	else :  #  this isn't pre-check flag , maybe still jump into argument-check ..
		function_argument_check_offset = function_entry_address
		disassmbly_address_list_offset = disassmbly_address_list.index(function_argument_check_offset)

	#  2. analayis function argument-check

	function_argument_check_end_offset = 0
	function_main_c_offset = 0
	function_return_offset = 0

	for index in range(disassmbly_address_list_offset,disassmbly_address_list_length) :
		current_address = disassmbly_address_list[index]

		if index + 3 == disassmbly_address_list_length :
			break

		next_address = disassmbly_address_list[index + 1]
		next_next_address = disassmbly_address_list[index + 2]
		next_next_next_address = disassmbly_address_list[index + 3]

		if (('JUMPDEST' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode()) and 
			('PUSH1' == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode() or 'PUSH2' == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode()) and \
			#('PUSH1' == disassmbly_data.get_disassmbly_by_address(next_next_address).get_opcode() or 'PUSH2' == disassmbly_data.get_disassmbly_by_address(next_next_address).get_opcode()) and \
			not function_return_offset) :
			if (('MLOAD' == disassmbly_data.get_disassmbly_by_address(next_next_address).get_opcode()) or \
				('MLOAD' == disassmbly_data.get_disassmbly_by_address(next_next_next_address).get_opcode())) :
				continue

			function_return_offset = int(disassmbly_data.get_disassmbly_by_address(next_address).get_opcode_data(0),16)
		elif (('PUSH1' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode() or 'PUSH2' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode()) and \
			(disassmbly_data.get_disassmbly_by_address(next_address).get_opcode().startswith('SWAP')) and \
			not function_return_offset) :
			function_return_offset = int(disassmbly_data.get_disassmbly_by_address(current_address).get_opcode_data(0),16)
		elif (('POP' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode()) and \
			('PUSH1' == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode() or 'PUSH2' == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode()) and \
			not function_return_offset) :

			if not (disassmbly_data.get_disassmbly_by_address(next_next_address).get_opcode().startswith('DUP')) :
				function_return_offset = int(disassmbly_data.get_disassmbly_by_address(next_address).get_opcode_data(0),16)

		if 'JUMPDEST' == disassmbly_data.get_disassmbly_by_address(next_address).get_opcode() :
			function_argument_check_end_offset = current_address

			#  reverse to search the opcode push ..
			for reverse_index in range(index,disassmbly_address_list_offset,-1) :
				current_address = disassmbly_address_list[reverse_index]

				if ('PUSH1' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode() or 'PUSH2' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode()) :
					function_main_c_offset = int(disassmbly_data.get_disassmbly_by_address(current_address).get_opcode_data(0),16)
					break

			break

	function_argument_check_code = disassmbly_data.split_bytecode(function_argument_check_offset,function_argument_check_end_offset)
	
	if is_debug :
		print hex(function_entry_address),hex(function_argument_check_offset),hex(function_main_c_offset),hex(function_return_offset)

	if not function_main_c_offset or not function_return_offset :
 		return False

	if not 'JUMPDEST' == disassmbly_data.get_disassmbly_by_address(function_main_c_offset).get_opcode() :
		return False

	disassmbly_address_list_offset = disassmbly_address_list.index(function_main_c_offset)

	#  3. get function main code

	function_main_code_end_offset = 0

	for index in range(disassmbly_address_list_offset,disassmbly_address_list_length) :
		current_address = disassmbly_address_list[index]

		if 'JUMP' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode() :
			function_main_code_end_offset = current_address

			break

	if not function_main_code_end_offset  :
 		return False

	function_main_code = disassmbly_data.split_bytecode(function_main_c_offset,function_main_code_end_offset)

	#  4. get return code

	disassmbly_address_list_offset = disassmbly_address_list.index(function_return_offset)
	function_return_code_end_offset = 0

	for index in range(disassmbly_address_list_offset,disassmbly_address_list_length) :
		current_address = disassmbly_address_list[index]

		if  'STOP' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode() or \
			'RETURN' == disassmbly_data.get_disassmbly_by_address(current_address).get_opcode() :
			function_return_code_end_offset = current_address

			break

	if not function_return_code_end_offset  :
 		return False

	function_return_code = disassmbly_data.split_bytecode(function_return_offset,function_return_code_end_offset)

	function_code_object.append_bytecode(function_argument_check_code)
	function_code_object.append_bytecode(function_main_code)
	function_code_object.append_bytecode(function_return_code)

	if is_debug :
		print '<<<<<<'
		#function_pre_check_code.print_code()
		function_argument_check_code.print_code()
		function_main_code.print_code()
		function_return_code.print_code()
		print '>>>>>>'
		#function_code_object.print_code()

	return function_code_object

def print_code_data(code_data) :
	address_list = disassmbly_data.get_disassmbly_address_list()

	for address_index in address_list :
		opcode = disassmbly_data.get_disassmbly_by_address(address_index)

		print(address_index,':',opcode.get_opcode(),opcode.get_opcode_data())

def get_contract_functions_code(file_path,is_debug = False) :
	disasm_file_data = disassmbly_contract(file_path)

	if not disasm_file_data :
		if is_debug :
			print 'Not found disasm_file_data'

		return False

	if is_debug :
		print 'disasm_file_data :'

		disasm_file_data.print_code()

	disasm_file_contract_runtime_entry = get_contract_runtime_entry(disasm_file_data)

	if is_debug :
		print 'contract_runtime_entry =',disasm_file_contract_runtime_entry

	if not -1 == disasm_file_contract_runtime_entry :
		disasm_file_data = disasm_file_data.split_bytecode(disasm_file_contract_runtime_entry)

	if is_debug :
		print 'disasm_file_contract_runtime_data :'

		disasm_file_data.print_code()

	entry_list = get_function_entry(disasm_file_data)

	if is_debug :
		print 'entry_list :'

		entry_list.print_entry()
	
	if not entry_list :
		return False

	function_entry = {}

	for function_entry_index in entry_list.get_all_function_entry() :
		function_code = get_function_code(disasm_file_data,entry_list.get_function_entry_address(function_entry_index),is_debug)

		if is_debug :
			print 'function code %s -->' % function_entry_index
			function_code.print_code()

		function_entry[function_entry_index] = function_code

	return function_entry

def is_read_state_function(disassmbly_data) :
	'''
		example : 

		19 : JUMPDEST []
		20 : PUSH1 ['0x03']
		22 : SLOAD []
		23 : DUP2 []
		24 : JUMP []
		25 : JUMPDEST []

		contract read a storage data and return ,we can ignore that ..
	'''
	disassmbly_address_list = disassmbly_data.get_disassmbly_address_list()
	disassmbly_address_list_length = disassmbly_data.get_disassmbly_address_list_length()

	for index in range(disassmbly_address_list_length) :
		current_address = disassmbly_address_list[index]
		current_opcode = disassmbly_data.get_disassmbly_by_address(current_address)

		if index + 6 > disassmbly_address_list_length :
			break

		if  'JUMPDEST' == disassmbly_data.get_disassmbly_by_address(disassmbly_address_list[index]).get_opcode() and \
			'PUSH1' == disassmbly_data.get_disassmbly_by_address(disassmbly_address_list[index + 1]).get_opcode() and \
			'SLOAD' == disassmbly_data.get_disassmbly_by_address(disassmbly_address_list[index + 2]).get_opcode() and \
			'DUP2' == disassmbly_data.get_disassmbly_by_address(disassmbly_address_list[index + 3]).get_opcode() and \
			'JUMP' == disassmbly_data.get_disassmbly_by_address(disassmbly_address_list[index + 4]).get_opcode() and \
			'JUMPDEST' == disassmbly_data.get_disassmbly_by_address(disassmbly_address_list[index + 5]).get_opcode() :
			return True

	return False

def is_mapping_object(disassmbly_code) :
	'''
		In solidity ,mapping object be complie to function .
		So we can see that many contract using mapping object ,if check tow contracts simulator . 
		This mapping object's simhash value is 1 .
	'''

	disassmbly_address_list = disassmbly_code.get_disassmbly_address_list()
	disassmbly_address_list_length = disassmbly_code.get_disassmbly_address_list_length()
	last_opcode = disassmbly_code.get_disassmbly_by_address(disassmbly_address_list[ -1 ])

	if not 'RETURN' == last_opcode.get_opcode() :
		return False

	bingo_point = 0
	function_data_count = 0

	for code_offset in range(disassmbly_address_list_length) :
		if code_offset + 3 > disassmbly_address_list_length :
			break

		current_opcode = disassmbly_code.get_disassmbly_by_address(disassmbly_address_list[code_offset])
		next_opcode = disassmbly_code.get_disassmbly_by_address(disassmbly_address_list[code_offset + 1])
		next_next_opcode = disassmbly_code.get_disassmbly_by_address(disassmbly_address_list[code_offset + 2])

		if 'CALLDATALOAD' == current_opcode.get_opcode() :
			function_data_count += 1
		elif 'SLOAD' == current_opcode.get_opcode() and \
			('JUMP' == next_opcode.get_opcode() or 'JUMP' == next_next_opcode.get_opcode()) :
			bingo_point += 1
		elif 'PUSH1' == current_opcode.get_opcode() and \
			'SHA3' == next_opcode.get_opcode() :
			bingo_point += 1

	if 1 == function_data_count and 2 == bingo_point :
		return True

	return False

filter_function = {
	'is_read_state_function' : is_read_state_function ,
	'is_mapping_object' : is_mapping_object
}

def get_function_simhash(code_data) :
	def get_features(data) :
		new_data = []

		for opcode_index in data.get_disassmbly_address_list() :
			new_data.append(data.get_disassmbly_by_address(opcode_index).get_opcode())

		return new_data

	code_data_simhash_list = {}

	for function_entry_index in code_data :
		function_code = code_data[function_entry_index]
		is_filter = False

		for filter_function_index in filter_function.keys() :  #  filter some function
			if filter_function[filter_function_index](function_code) :
				is_filter = True

				break

		if not is_filter :
			code_data_simhash_list[function_entry_index] = Simhash(get_features(code_data[function_entry_index]))

	return code_data_simhash_list

def merge_simhash_check(code_data1,code_data2) :
	merge_result = {}

	for code_data1_function_index in code_data1.keys() :
		min_distance = 200  #  no distance bigger than this number ..
		current_function_hash = ''

		for code_data2_function_index in code_data2.keys() :
			current_distance = code_data1[code_data1_function_index].distance(code_data2[code_data2_function_index])

			if current_distance < min_distance :
				min_distance = current_distance
				current_function_hash = code_data2_function_index

		#  I try some simulator function code (modify little code ).If they are simluar ,the distance value is <= 6 .

		merge_result['%s_%s' % (code_data1_function_index,current_function_hash)] = float('%.2f' % pow(DISTANCE_BASE_NUMBER,min_distance))  #  luck nunmber ..

	return merge_result

def calculate_merge_result(merge_result) :
	point = 0.0

	for merge_index in merge_result :
		if merge_result[merge_index] >= SIMULATOR_VALID_VALUE_LEVEL_2 :  #  1.0 is max simualte value ..
			point += 1.2
		elif merge_result[merge_index] >= SIMULATOR_VALID_VALUE_LEVEL_1 :  #  0.6 is simualte value ..
			point += 1.0

	return point / len(merge_result)

def check_contract_simulate(code_data1,code_data2,is_debug = False) :
	if is_debug :
		print code_data1
		print '---'
		print code_data2

	if not code_data1 or not code_data2 :
		return False,-1

	function_simhash1 = get_function_simhash(code_data1)
	function_simhash2 = get_function_simhash(code_data2)

	if not function_simhash1 or not function_simhash2 :
		return False,-2

	if is_debug :
		print function_simhash1
		print function_simhash2

	merge_simhash_result1 = merge_simhash_check(function_simhash1,function_simhash2)
	merge_simhash_result2 = merge_simhash_check(function_simhash2,function_simhash1)

	if is_debug :
		print merge_simhash_result1
		print merge_simhash_result2

	merge_rate1 = calculate_merge_result(merge_simhash_result1)
	merge_rate2 = calculate_merge_result(merge_simhash_result2)

	if is_debug :
		print merge_rate1
		print merge_rate2

	simualte_value = merge_rate1 * merge_rate2

	if simualte_value >= SIMULATOR_ALERT_VALUE :
		return True,simualte_value

	return False,simualte_value

def write_data(file_path,data) :
	file = open(file_path,'w')

	file.write(data)
	file.close()


print_queue = Queue.Queue()
work_queue = Queue.Queue()
result_queue = Queue.Queue()
except_queue = Queue.Queue()


def work_thread(simple_file_code_list) :
	while not work_queue.empty() :
		try :
			check_file_path = work_queue.get(False,1)
		except :
			break

		if not -1 == check_file_path.find('/') :
			contract_address = check_file_path.split('/')[-1]
		else :
			contract_address = check_file_path

		try :
			check_file_code = get_contract_functions_code(check_file_path)
		except :
			print_queue.put('Check Contract %s make except !!' % (contract_address))
			except_queue.put(check_file_path)

			continue

		check_point = 0
		check_type = ''
		is_except = False

		#print_queue.put('Checking Contract %s ' % (check_file_path))

		for simple_file_code_object in simple_file_code_list :
			simple_file_name = simple_file_code_object[0]
			simple_file_code = simple_file_code_object[1]

			try :
				check_result = check_contract_simulate(check_file_code,simple_file_code)
			except :
				is_except = True

				break

			if -1 == check_result[1] :  #  analayis code except 
				break
			elif not check_result[0] :  #  no matching code type 
				continue

			if not -1 == simple_file_name.find('/') :
				simple_file_name = simple_file_name.split('/')[-1]

			if check_point < check_result[1] :
				check_point = check_result[1]
				check_type = simple_file_name.split('_')[0]

		if check_type :
			print_queue.put('Contract %s  Result Type:%s  Check Point:%s' % (contract_address,check_type,check_point))
			result_queue.put((contract_address,check_type))
		elif is_except :  #  no print ..
			print_queue.put('Check Contract %s make except !!' % (contract_address))
			except_queue.put(check_file_path)
		else :
			print_queue.put('Not found  %s' % (contract_address))

def check_has_alive_thread(work_thread_object_list) :
	has_alive = False

	for work_thread_index in work_thread_object_list :
		if work_thread_index.isAlive() :
			has_alive = True

			break

	return has_alive


if __name__ == '__main__' :
	usage = '''
	Using : 
	  python check.py optional file_path1 file_path2
	Optional :
	  -f , --check_file  check tow contract file simulate
	  -d , --check_dir   check tow dir's file simulate
	  -t , --thread      running threading
	  -b , --debug       enable debug output
	Example :
	  python check.py --check_file simple/erc20_contract1.txt simple/erc701_contract1.txt
	  python check.py --check_dir %simple_path% %check_contract_path%
	  python check.py --check_dir simple eth_contract
	'''

	parser = OptionParser(usage)

	parser.add_option('-f','--check_file',action = 'store_true',default = False)
	parser.add_option('-d','--check_dir',action = 'store_true',default = False)
	parser.add_option('-t','--thread',action = 'store',default = False)
	parser.add_option('-b','--debug',action = 'store_true',default = False)

	(options,args) = parser.parse_args()

	if 2 > len(args) :
		parser.print_usage()

		exit()

	thread_number = 1

	if options.thread :
		try :
			thread_number = int(options.thread)
		except :
			parser.print_usage()

			exit()

	if options.check_file :
		code_data1 = get_contract_functions_code(args[0],options.debug)
		code_data2 = get_contract_functions_code(args[1],options.debug)

		print check_contract_simulate(code_data1,code_data2,options.debug)
	elif options.check_dir :
		simple_file_list = os.listdir(args[0])
		check_file_list = os.listdir(args[1])
		except_contract = []
		result = {}

		if 1 == thread_number :
			simple_code_list = []

			for simple_file_index in simple_file_list :
				simple_file_path = '%s/%s' % (args[0],simple_file_index)
				simple_file_code = get_contract_functions_code(simple_file_path)

				simple_code_list.append((simple_file_index,simple_file_code))

			for check_file_index in check_file_list :
				check_file = '%s/%s' % (args[1],check_file_index)
				try :
					check_file_code = get_contract_functions_code(check_file)
				except :
					print 'Load Contract',check_file,'except !!'

					except_contract.append(check_file)

					continue

				check_point = 0
				check_type = ''

				print 'Checking',check_file

				for simple_code_index in simple_code_list :
					simple_file_name = simple_code_index[0]
					simple_file_code = simple_code_index[1]

					try :
						check_result = check_contract_simulate(simple_file_code,check_file_code)
					except :
						print 'Check Contract',check_file,'except !!'

						except_contract.append(check_file)

						break

					if -1 == check_result[1] :  #  analayis code except 
						break
					elif not check_result[0] :  #  no matching code type 
						continue

					if check_point < check_result[1] :
						check_point = check_result[1]
						check_type = simple_file_name.split('_')[0]

				if check_type :
					print 'Result Type:',check_type,'  Check Point:',check_point

					result[check_file_index] = check_type
				else :
					print 'Not found  %s' % (check_file_index)
		elif 2 <= thread_number :
			simple_file_code = []

			print 'Loading Simple File'

			for simple_file_index in simple_file_list :
				simple_file_code_data = get_contract_functions_code('%s/%s' % (args[0],simple_file_index))

				simple_file_code.append((simple_file_index,simple_file_code_data))

			for check_file_index in check_file_list :
				work_queue.put('%s/%s' % (args[1],check_file_index))

			work_thread_object_list = []

			print 'Creating Thread'

			for create_thread_index in range(thread_number) :
				work_thread_object = threading.Thread(target = work_thread,args = (simple_file_code,))
				work_thread_object.daemon = True

				work_thread_object.start()
				work_thread_object_list.append(work_thread_object)

			while check_has_alive_thread(work_thread_object_list) or not print_queue.empty() :
				while not print_queue.empty() :
					print print_queue.get()

				time.sleep(1)

			print 'Processing Data ..'

			while not result_queue.empty() :
				contract_result = result_queue.get()
				result[contract_result[0]] = contract_result[1]

			while not except_queue.empty() :
				except_contract.append(except_queue.get())

		write_data('./eth_contract_report.txt',json.dumps(result))
		write_data('./eth_contract_except.txt',json.dumps(except_contract))

		print 'Exit'

		exit()

	'''
	print Simhash(file_data1).value
	print Simhash(file_data2).value
	print Simhash(file_data1).distance(Simhash(file_data2))
	print Simhash(get_features(file_data1)).value
	print Simhash(get_features(file_data2)).value
	print Simhash(get_features(file_data1)).distance(Simhash(get_features(file_data2)))
	'''
