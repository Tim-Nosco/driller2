import os
import angr, claripy
import logging
from hashlib import md5

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

def main():
	base_path = "/job/target/"
	ld_path  = base_path+"lib"
	#inputs: CMD, input stream, input testcase filename
	CMD = [base_path+"CGC_Hangman_Game"]
	corpus = base_path+"corpus/"
	input_testcase = corpus+"0"

	#read testcase
	with open(input_testcase, "rb") as f:
		input_data = f.read()
	logger.info("Read %d bytes from testcase: %s.", len(input_data), input_testcase)

	#load the binary with the specified libraries
	logger.debug("Creating angr project.")
	p = angr.Project(CMD[0], 
		except_missing_libs=True, 
		ld_path=(ld_path))
	#create the entry state
	logger.debug("Initializing entry state.")
	s = p.factory.full_init_state(
		mode="tracing",
		args=CMD,
		stdin=angr.SimFileStream
	)
	#assert the current testcase
	s.preconstrainer.preconstrain_file(input_data,s.posix.stdin,True)
	#initialize the manager
	simgr = p.factory.simgr(s, save_unsat=True, auto_drop={'missed', 'processed'})
	#a state may be unsat only because of the file constraint
	def valid_transition(state):
		#TODO: checkbitmap for necessity
		logger.debug("Checking if %s is a valid transition.", state)
		state.preconstrainer.remove_preconstraints()
		return state.satisfiable()
	#while there is a state in active
	while simgr.active:
		#make sure we're on a reasonable path
		if len(simgr.active) > 1:
			logger.critical("More than one active state.")
			raise("Too many active states.")
		#step the active state
		logger.debug("Stepping %s", simgr.one_active)
		logger.debug("Start: %s", simgr)
		simgr.step()
		logger.debug("End:   %s", simgr)
		#if states were unsat, check if they would have been valid
		#without the stdin constraints
		if simgr.unsat:
			#save valid states to diverted
			simgr.move(
				from_stash='unsat', to_stash='diverted',
				filter_func=valid_transition
			)
			#throw away the others
			logger.debug("Clearing the unsat cache of %d states.", 
				len(simgr.unsat))
			simgr.move(from_stash='unsat', to_stash='missed')
		for s in simgr.stashes['diverted']:
			logger.info("Generated a new path!")
			#pull out a valid stdin and write it to the corpus
			data = s.posix.stdin.concretize()
			name = corpus+md5(data).hexdigest()
			logger.debug("Saving %d bytes to %s", len(data), name)
			with open(name, 'wb') as f:
				f.write(data)
		logger.debug("Clearing the diverted stash of %d states.", 
			len(simgr.stashes['diverted']))
		simgr.move(from_stash='diverted', to_stash='processed')
	hook(locals())


if __name__ == '__main__':
	logger.setLevel(logging.DEBUG)
	main()
