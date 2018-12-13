import os
import angr, claripy
import logging
from hashlib import md5
import time
import multiprocessing as mp
from functools import partial

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
			name = "%s/id:%06d"%(corpus,counter,md5(data).hexdigest())
			logger.debug("Saving %d bytes to %s", len(data), name)
			with open(name, 'wb') as f:
				f.write(data)
		return r

	#while there is a state in active
	avg_step = (0.0, 0)
	total_time = time.time()
	processes = []
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
		avg_step = update_avg(start, *avg_step)
		logger.debug("End:   %s", simgr)
		#if states were unsat, check if they would have been valid
		#without the stdin constraints
		for s in simgr.unsat:
			p = mp.Process(target=valid_transition, 
				args=(s,id_counter))
			p.start()
			processes.append(p)
			id_counter += 1
		#throw away the others
		logger.debug("Clearing the unsat cache of %d states.", 
			len(simgr.unsat))
		simgr.drop(stash='unsat')
	for p in processes:
		p.join()
	total_time = time.time() - total_time
	print("Time stepping concrete state: %.02fs %s" % (
		avg_step[0]*avg_step[1], avg_step))
	print("Total runtime:                %.02fs" % total_time)
	#hook(locals())


if __name__ == '__main__':
	logger.setLevel(logging.DEBUG)
	try:
		logger.debug("Creating output directory")
		os.mkdir("/dev/shm/corpus/")
	except FileExistsError as e:
		logger.warning("Corpus folder already exists")
	main(
		["/job/target/CGC_Hangman_Game"], 
		"/dev/shm/corpus/", 
		"/job/target/corpus/0",
		"/job/target/lib"
	)
