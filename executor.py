#!env python3
import os
import angr
import logging
from hashlib import md5
import time
import multiprocessing as mp

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

def valid_transition(state,counter,corpus,infile):
	#a state may be unsat only because of the file constraint
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

def main(command, corpus, testcase, ld_path, input_stream):
	logger.debug("executor.main(%r, %r, %r, %r, %r)", 
		command, corpus, testcase, ld_path, input_stream)
	#read testcase
	with open(testcase, "rb") as f:
		input_data = f.read()
	logger.info("Read %d bytes from testcase: %s.", len(input_data), testcase)

	#load the binary with the specified libraries
	logger.debug("Creating angr project.")
	p = angr.Project(command[0], 
		except_missing_libs=True, 
		ld_path=ld_path)
	#create the entry state
	logger.debug("Initializing entry state.")
	#assert the current testcase
	in_stream_file = angr.SimFileStream(testcase)
	if input_stream == "___STDIN___":
		logger.debug("Making stdin symbolic.")
		s = p.factory.full_init_state(
			mode="tracing",
			args=command,
			stdin=in_stream_file
		)
	else:
		logger.debug("Making symbolic file: %s", testcase)
		s = p.factory.full_init_state(
			# mode="tracing",
			args=command,
			concrete_fs=False,
			fs={testcase:in_stream_file}
		)
	logger.debug("Constraining %r", in_stream_file)
	s.preconstrainer.preconstrain_file(input_data,in_stream_file,True)
	#initialize the manager
	logger.debug("Creating simulation manager")
	simgr = p.factory.simgr(s, save_unsat=True)
	#use an id to produce reasonable file names
	id_counter = 0
	avg_step = (0.0, 0)
	total_time = time.time()
	#use a pool of process to limit the total processes spawned
	logger.debug("Allocating process pool")
	with mp.Pool(processes=4) as pool:
		#explore the concrete path
		#while there is a state in active
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
				if input_stream=="___STDIN___":
					in_stream_file = s.posix.stdin
				else:
					in_stream_file = s.fs.get(testcase) 
				pool.apply_async(valid_transition, 
					(s,id_counter,corpus,in_stream_file))
				id_counter += 1
			if simgr.unsat:
				#throw away the unneeded unsat states
				logger.debug("Clearing the unsat cache of %d states.", 
					len(simgr.unsat))
				simgr.drop(stash='unsat')
	#Print some timing stuff
	total_time = time.time() - total_time
	print("Time stepping concrete state: %.02fs %s" % (
		avg_step[0]*avg_step[1], avg_step))
	print("Total runtime:                %.02fs" % total_time)

