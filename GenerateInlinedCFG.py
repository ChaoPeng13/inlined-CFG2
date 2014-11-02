import os, glob, sys, pickle, struct, collections

NM = "NM/" # The directory of nm files
OBJDUMP = "OBJDUMP/" # The directory of  objdump files
DOT = "DOT/" # The directory of dot files
RESULT = "RESULT/" # The directory of inlined-CFG results in a curtain data format

dict_all_inst = dict()
dict_all_bb = dict()

dict_all_labels = dict() # Record all possible function labels from .nm file 
dict_all_functions = dict() # Record all functions from .ob file based on the start address
dict_valid_functions = dict() # Record all valid functions based on abstract execution
main_at = list()

TYPES = ["Normal", "Unconditional", "Conditional", "FuncCall", "BX", "BLX"]

def full_addr(address): #Get full 32bit address
	temp = '00000000'
	return temp[:8-len(address)]+address

def check_hex(address):
	alphabet = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
	for k in range(len(address)):
		if not address[k] in alphabet:
			return False
	return True

def prev_inst_addr(address): # The 32bit address of the previous instruction
	#print address
	addr = int(address,16)
	addr = addr - 4
	addr_str = str('%x' % addr)
	return full_addr(addr_str)

def compare(in1,in2): # if in1 > in2, return true; otherwise return false
	return int(in1,16) > int(in2,16)


class Instruction:
	def __init__ (self, address, expr_hexadecimal, expr_text, func, bb=None, inst_type = None, jump_to_addr = None, jump_to_func = None):
		self.address = address
		self.expr_hexadecimal = expr_hexadecimal
		self.expr_text = expr_text
		self.inst_type = inst_type #{Normal, Unconditional, Conditional, FuncCall, BX, BLX}
		self.jump_to_addr = jump_to_addr # If jump to function, this jump_to = <...>, otherwise hexadecimal
		self.jump_to_func = jump_to_func
		self.func = func
		self.bb = bb

	def update_inst(self):
		fields = self.expr_text.split()
		if (fields[0][0:2] == 'bl' and dict_all_labels.has_key(full_addr(fields[1]))):
			self.inst_type = 'FuncCall'
			self.jump_to_addr = full_addr(fields[1])
			self.jump_to_func = fields[2][1:-1]
		elif (fields[0] == "b"):
			self.inst_type = 'Unconditonal'
			self.jump_to_addr = full_addr(fields[1])
			self.jump_to_func = None
		elif (fields[0] == "BX"):
			self.inst_type = 'BX'
			self.jump_to_addr = None
			self.jump_to_func = None
		elif (fields[0] == "BLX"):
			self.inst_type = 'BLX'
			self.jump_to_addr = None
			self.jump_to_func = None
		elif (fields[0][0] == 'b' and len(fields[0]) != 1):
			self.inst_type = 'Conditonal'
			self.jump_to_addr = full_addr(fields[1])
			self.jump_to_func = None
		else:
			self.inst_type = "Normal"


	def get_inst_info(self):
		inst_info = "Address:%s Function:%s BasicBlock:%s Text:%s" % (self.address, self.func.name, self.bb, self.expr_text)
		return inst_info


class BasicBlock:
	def __init__(self, name, func, start = None, end = None, size = 0):
		self.name = name
		self.start = start
		self.end = end
		self.size = size
		self.jump_to = None
		self.loop_to = None
		self.call_to = None
		self.func = func
		self.nextbb = None

		self.list_inst = list()

	def add_inst(self,inst):
		if (len(self.list_inst)==0):
			self.start = inst.address
			self.end = inst.address

			self.size = 4
			self.list_inst.append(inst)
		else:
			#assert int(self.list_inst[-1].address,16) == int(inst.address,16) - 4
			self.size += 4
			self.end = inst.address
			self.list_inst.append(inst)
		assert len(self.list_inst) > 0

	def get_list_inst(self):
		return self.list_inst

	def get_bb_info(self):
		bb_info = "Name:%s Function:%s Start:%s End:%s Size:%d jump_to:%s loop_to:%s call_to:%s" % (self.name,self.func.name,self.start,self.end,self.size, self.jump_to,self.loop_to,self.call_to)
		for inst in self.list_inst:
			bb_info += "\n" + inst.get_inst_info()
		return bb_info

class Function:
	def __init__(self, name, start, end = None, size = 0):
		self.name = name
		self.start = start
		self.end = end
		self.size = size

		self.list_inst = list()
		self.list_bb = list()

	def add_inst(self,inst):
		inst.update_inst()
		dict_all_inst[inst.address] = inst
		self.end = inst.address
		self.list_inst.append(inst)
		self.size += 4
		assert self.size/4 == len(self.list_inst)
			

	def create_bb(self):
		assert len(self.list_inst) != 0
		assert len(self.list_bb) == 0

		boundaries = list()

		#first time traverse list_inst to get the boundaries of basic blocks
		for inst in self.list_inst:
			if inst.inst_type != "Normal":
				boundaries.append(inst.address)
				jump_to = inst.jump_to_addr
				if inst.inst_type == "BX" or inst.inst_type == "BLX":
					continue
				if not check_hex(jump_to):
					continue

				if not dict_all_functions.has_key(jump_to):
					#print inst.inst_type
					if not prev_inst_addr(jump_to) in boundaries:
						boundaries.append(prev_inst_addr(jump_to))

		#Second time traverse list_bb to generate basic blocks of this function
		bb = BasicBlock(self.list_inst[0].address, self)
		self.list_bb.append(bb)
		#print len(self.list_inst)
		for inst in self.list_inst:
			#print inst.address
			if prev_inst_addr(inst.address) in boundaries:
				bb = BasicBlock(inst.address, self)
				self.list_bb.append(bb)
			bb.add_inst(inst)

			

		#Generate next basic block for each basic block
		for k in range(len(self.list_bb)):
			dict_all_bb[self.list_bb[k].name]=self.list_bb[k]
			if k != len(self.list_bb)-1:
				self.list_bb[k].nextbb = self.list_bb[k+1]

	def create_links(self):
		#First time traverse list_bb to create links of this function
		assert len(self.list_bb) != 0
		for temp in self.list_bb:
			for inst in temp.get_list_inst():
				inst.bb = temp
			#print temp.get_bb_info()
			assert len(temp.get_list_inst()) > 0
			inst = temp.list_inst[-1]
			if inst.inst_type == "FuncCall" :
				temp.call_to = inst.jump_to_addr
			elif (inst.inst_type == "Unconditional" 
				or inst.inst_type == "Conditional"):
				if(compare(inst.jump_to_addr,inst.address)):
					temp.jump_to = inst.jump_to_addr
				else:
					temp.loop_to = inst.jump_to_addr
			else:
				if (inst.address != self.end):
					assert temp.nextbb != None

	def get_func_info(self):
		func_info = "Function:%s Start:%s End:%s Size:%d" % (self.name, self.start, self.end, self.size)
		for temp in self.list_bb:
			func_info += "\n" + temp.get_bb_info()

		return func_info

	def get_list_bb(self):
		return self.list_bb

def output_info(func,f1):
	f1.write("%s" % func.get_func_info())

def funcDOT(func,f1,f2):
	output_info(func, f2)
	for temp in func.get_list_bb():
		if (temp.nextbb != None):
			f1.write("	%s -> %s\n" % (temp.name, temp.nextbb.name))

		if (temp.jump_to != None):
			f1.write("	%s -> %s\n" % (temp.name, temp.jump_to))

		if (temp.loop_to != None):
			f1.write("	%s -> %s\n" % (temp.name, temp.loop_to))

		if (temp.call_to != None):
			f1.write("	%s -> %s\n" % (temp.name, dict_all_functions[temp.call_to].name))
			#generateDOT(dict_all_functions[temp.call_to], f1,f2)
			f1.write("	%s -> %s\n" % (dict_all_functions[temp.call_to].name,temp.nextbb.name))

		
def generateDOT(func,file1,file2):
	f1 = open (file1, "w")
	f2 = open (file2, "w")
	f1.write("digraph G {")
	funcDOT(func, f1, f2)
	f1.writelines("}")
	f1.close()
	f2.close()

def get_all_lables(nm): # Get all labels from .nm file and update dict_all_labels
	for line in file(nm):
		fields = line.split()
		if (len(fields) < 3):
			continue
		if line.rstrip().endswith(" T main"):
			main_at.append(full_addr(fields[0]))

		dict_all_labels[full_addr(fields[0])] = fields[-1]

def get_all_functions(od): # Get all functions from .od file and update dict_all_functions
	flag = False
	for line in file(od):
		fields = line.split()
		if (len(fields) == 2 and len(fields[0])==8):
			flag = True
			assert dict_all_labels.has_key(full_addr(fields[0]))
			func = Function(fields[1][1:-2], full_addr(fields[0]))
			dict_all_functions[full_addr(fields[0])] = func
			continue

		if (len(fields)==0):
			continue

		if len(fields[0]) > 8:
			continue

		if flag and len(fields) >= 4:
			if (len(fields[0][:-1]) >= 4 and fields[2] != ".word"): # Instructions
				address = full_addr(fields[0][:-1])
				expr_hexadecimal = fields[1]
				expr_text = ' '.join(fields[2:])
				inst = Instruction(address, expr_hexadecimal, expr_text, func)
				func.add_inst(inst)

def update_all_functions():
	assert len(dict_all_functions) > 0
	for key in dict_all_functions:
		dict_all_functions[key].create_bb()
		dict_all_functions[key].create_links()


if __name__ == '__main__':
	assert len(sys.argv) == 6
	#print sys.argv[1]
	get_all_lables(sys.argv[2])
	assert len(main_at) == 1
	#print main_at[0]
	get_all_functions(sys.argv[3])
	#print dict_all_functions
	update_all_functions()

	generateDOT(dict_all_functions[main_at[0]], sys.argv[4], sys.argv[5])




















