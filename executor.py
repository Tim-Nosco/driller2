#!env python3
import os
import angr
import logging
from hashlib import md5
import time
import multiprocessing as mp
import argparse, shlex

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
	#a state may be unsat only because of the file constraint
	#use an id to produce reasonable file names
	id_counter = 0
	def valid_transition(state,counter):
		#TODO: checkbitmap for necessity
		logger.debug("Checking if %s is a valid transition.", state)
		start = time.time()
		state.preconstrainer.remove_preconstraints()
		r = state.satisfiable()
		if r:
			logger.info("Generated a new path!")
			#pull out a valid stdin and write it to the corpus
			data = state.posix.stdin.concretize()
			name = "%s/id:%06d_%s"%(corpus,counter,md5(data).hexdigest())
			logger.debug("Saving %d bytes to %s", len(data), name)
			with open(name, 'wb') as f:
				f.write(data)
		return r

	#while there is a state in active
	avg_step = (0.0, 0)
	total_time = time.time()
	#use a pool of process to limit the total processes spawned
	with mp.Pool(processes=4) as pool:
		#explore the concrete path
		while simgr.active:
			#make sure we're on a reasonable path
			if len(simgr.active) > 1:
				logger.critical("More than one active state.")
				raise("Too many active states.")
			#step the active state
			logger.debug("Stepping %s", simgr.one_active)
			logger.debug("Start: %s", simgr)
			start = time.time()
			simgr.step()
			avg_step = update_avg(time.time()-start, *avg_step)
			logger.debug("End:   %s", simgr)
			#if states were unsat, check if they would have been valid
			#without the stdin constraints
			for s in simgr.unsat:
				#this check can be done in an independant process
				pool.apply_async(valid_transition, (s,id_counter))
				id_counter += 1
			#throw away the unneeded unsat states
			logger.debug("Clearing the unsat cache of %d states.", 
				len(simgr.unsat))
			simgr.drop(stash='unsat')
	#Print some timing stuff
	total_time = time.time() - total_time
	print("Time stepping concrete state: %.02fs %s" % (
		avg_step[0]*avg_step[1], avg_step))
	print("Total runtime:                %.02fs" % total_time)

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
