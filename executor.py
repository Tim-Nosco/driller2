import angr, claripy
import logging

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
logger = logging.getLogger('executor.py')

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
	input_stream = "/dev/stdin"
	input_testcase = base_path+"corpus/0"

	#read testcase
	with open(input_testcase, "rb") as f:
		input_data = f.read()
	#load the binary with the specified libraries
	p = angr.Project(CMD[0], except_missing_libs=True, ld_path=(ld_path))

	#initialize the concrete state with unicorn options and it's input data fixed
	#TODO do not hardcode STDIN
	concrete_state = p.factory.full_init_state(
		add_options=angr.options.unicorn,
		args = CMD,
		stdin = input_data
	)
	concrete_sm = p.factory.simgr(concrete_state)

	#initialize the symbolic state
	symbolic_state = p.factory.full_init_state(
		args = CMD
	)
	symbolic_sm = p.factory.simgr(symbolic_state)

	#step both until symbolic_sm has more than one path
	while len(symbolic_sm.active) == 1 and len(concrete_sm.active)==1:
		logger.info("Stepping symbolic: %s", symbolic_sm)
		symbolic_sm.step()
		logger.info("Stepping concrete: %s", concrete_sm)
		concrete_sm.step()

	hook(locals())


if __name__ == '__main__':
	main()