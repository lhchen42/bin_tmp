import sys
import os
import numpy as np
import angr
from angrutils import *


class ProgramVectors:
	def __init__(self, nodes:dict = None):
		if(nodes):
			self.nodes = nodes
		else:
			self.nodes = dict()

	def get_node(self, addr):
		return self.nodes[addr]
	
	def get_all_nodes(self):
		return self.nodes
	
	def insert_node(self, addr, node_vector):
		self.nodes[addr] = node_vector

class NodeVector(ProgramVectors):
	def __init__(self, addr: int = None, vector : list() = None, sucessors : list() = None, predecessors : list() = None):
		if(addr):
			self.addr = addr
		if(vector):
			self.vector = vector
		if(sucessors):
			self.sucessors = sucessors
		if(predecessors):
			self.predecessors = predecessors
	def get_vector(self):
		return self.vector
	def get_sucessors(self):
		return self.sucessors
	def get_predessors(self):
		return self.predecessors

def Node_Vector(node, proj):
	block_vex = proj.factory.block(node.addr).vex
	c_Store = c_Put = c_PutI = c_WrTmp = c_LoadG = c_StoreG = c_CAS =  0
	for stmt in block_vex.statements:
		if isinstance(stmt, pyvex.IRStmt.Store):
			c_Store+=1
		elif isinstance(stmt, pyvex.IRStmt.Put):
			c_Put+=1
		elif isinstance(stmt, pyvex.IRStmt.PutI):
			c_PutI+=1
		elif isinstance(stmt, pyvex.IRStmt.WrTmp):
			c_WrTmp+=1
		elif isinstance(stmt, pyvex.IRStmt.LoadG):
			c_LoadG+=1
		elif isinstance(stmt, pyvex.IRStmt.StoreG):
			c_StoreG+=1
		elif isinstance(stmt, pyvex.IRStmt.CAS):
			c_CAS+=1
	vector = [c_Store, c_Put, c_WrTmp, c_LoadG, c_StoreG, c_CAS, len(node.successors), len(node.predecessors)]
	return NodeVector(node.addr, vector, node.successors, node.predecessors)


def main():
	if(os.path.isdir(sys.argv[1])):
		directory = os.fsencode(sys.argv[1])
		output_file = sys.argv[2]
		print(directory)

		with open(output_file, "w") as fl:
			for file in os.listdir(directory):
				filename = os.fsencode(file)
				file_path = directory + filename
				#print(file_path)
				try:
					proj = angr.Project(file_path.decode(), load_options={'auto_load_libs': False})
				except Exception as e:
					print(e)
					sys.exit()
				cfg = proj.analyses.CFGFast()
				_PV = ProgramVectors()
				for node in cfg.graph.nodes:
					node_vector = Node_Vector(node, proj)
					_PV.insert_node(node.addr, node_vector)

				vector_array = [_PV.get_node(node).get_vector() for node in _PV.get_all_nodes()]
				vector_array = np.asarray(vector_array)
				#print(vector_array)
				s = np.zeros(8) # sum
				for v in vector_array:
					s+=v
				#write into files: filename, features
				s=s.astype(int)
				print(f'write: {filename.decode()},{s[0]},{s[1]},{s[2]},{s[3]},{s[4]},{s[5]},{s[6]},{s[7]}\n')
				fl.write(f'{filename.decode()},{s[0]},{s[1]},{s[2]},{s[3]},{s[4]},{s[5]},{s[6]},{s[7]}\n')


if __name__ == "__main__":
	main()
