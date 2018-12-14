#!env python3
import os
import angr
import logging
from hashlib import md5
import time
import multiprocessing as mp
import argparse

root_logger = logging.getLogger()
root_logger.setLevel(logging.WARNING)
logger = logging.getLogger(name=__name__)

def hook(l=None):
	#useful for testing
	if l!=None:
		locals().update(l)
	import IPython
	IPython.embed(banner1="", confirm_exit=False)
	exit(0)

def update_avg(xnp1, cma, n):
	return cma+((xnp1 - cma)/(n+1)), n+1

class driller_no_trace(angr.exploration_techniques.ExplorationTechnique):
	def __init__(self, corpus, input_file="stdin", fuzz_bitmap=None):
		self.corpus = corpus
		self.fuzz_bitmap = fuzz_bitmap or b"\xff" * 65536
		self.id_counter=0
		self.pool = mp.Pool(processes=4)
		self.avg_step = (0.0, 0)
		if input_file=="stdin":
			self.input = lambda s: s.posix.stdin
		else:
			self.input = lambda s: s.fs.get(input_file)

	def setup(self, simgr):
		#TODO: set save_unsat
		self.project = simgr._project

	def step(self, simgr, stash="active", **kwargs):
		#make sure we're on a reasonable path
		if len(simgr.active) > 1:
			logger.critical("More than one active state.")
			raise("Too many active states.")
		#step the active state
		logger.debug("Stepping %s", simgr.one_active)
		logger.debug("Start: %s", simgr)
		start = time.time()
		simgr.step(stash=stash, **kwargs)
		self.avg_step = self._update_avg(time.time()-start, *self.avg_step)
		logger.debug("End:   %s", simgr)
		#if states were unsat, check if they would have been valid
		#without the stdin constraints
		for s in simgr.unsat:
			#this check can be done in an independent process
			self.pool.apply_async(valid_transition, 
				(self.input(s),self.corpus,s,self.id_counter))
			self.id_counter += 1
		simgr.drop(stash='unsat')


	def _update_avg(self, xnp1, cma, n):
		return cma+((xnp1 - cma)/(n+1)), n+1

def valid_transition(infile, corpus, state, counter):
	#TODO: checkbitmap for necessity
	logger.debug("Checking if %s is a valid transition.", state)
	state.preconstrainer.remove_preconstraints()
	r = state.satisfiable()
	if r:
		logger.info("Generated a new path!")
		#pull out a valid stdin and write it to the corpus
		data = infile.concretize()
		name = "%s/id:%06d_%s"%(corpus,counter,md5(data).hexdigest())
		logger.debug("Saving %d bytes to %s", len(data), name)
		with open(name, 'wb') as f:
			f.write(data)
	return r


def main(command, corpus, testcase, ld_path):
	#read testcase
	with open(testcase, "rb") as f:
		input_data = f.read()
	logger.info("Read %d bytes from testcase: %s.", len(input_data), testcase)

	#load the binary with the specified libraries
	logger.debug("Creating angr project.")
	p = angr.Project(command[0], 
		except_missing_libs=True, 
		ld_path=(ld_path))
	#create the entry state
	logger.debug("Initializing entry state.")
	s = p.factory.full_init_state(
		mode="tracing",
		args=command,
		stdin=angr.SimFileStream
	)
	#assert the current testcase
	s.preconstrainer.preconstrain_file(input_data,s.posix.stdin,True)
	#initialize the manager
	simgr = p.factory.simgr(s, save_unsat=True)
	d = driller_no_trace(corpus)
	simgr.use_technique(d)
	start_time = time.time()
	simgr.run()
	total_time = time.time() - start_time
	print("Time stepping concrete state: %.02fs %s" % (
		d.avg_step[0]*d.avg_step[1], d.avg_step))
	print("Total runtime:                %.02fs" % total_time)
	return simgr

def _set_log_level(level):
	#interpret specified level
	if not hasattr(logging,level):
		logger.error("Invalid log level specified: %s", level)
		logger.error("Using INFO.")
		level = "INFO"
	#set the level
	logger.setLevel(getattr(logging,level))

if __name__ == '__main__':
	parser = argparse.ArgumentParser('executor.py', 
		description="Concollic executor emulating driller.")

	parser.add_argument("-v", "--log-level", default="INFO", 
		help="Set the log level.", dest="level",
		choices=["DEBUG","INFO","WARNING","ERROR","CRITICAL"])
	
	parser.add_argument("-l", "--ld-path")
	
	parser.add_argument("-i", "--input-file", required=True)
	
	parser.add_argument("-o", "--corpus", default="/dev/shm/corpus")

	parser.add_argument("command", nargs=argparse.REMAINDER)

	args=parser.parse_args()

	_set_log_level(args.level)

	try:
		logger.debug("Creating output directory: %s", args.corpus)
		os.mkdir(args.corpus)
	except FileExistsError as e:
		logger.warning("Corpus folder already exists")
	main(
		args.command, 
		args.corpus, 
		args.input_file,
		args.ld_path
	)
