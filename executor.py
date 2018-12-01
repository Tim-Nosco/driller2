import os
import angr, claripy, tracer
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

def do_trace(proj,input_data,**kwargs):
	#Function taken from: https://github.com/angr/angr/blob/master/tests/common.py#L19
	logging.getLogger("tracer").setLevel('DEBUG')
	runner = tracer.QEMURunner(project=proj, input=input_data, **kwargs)
	#Modify the trace so the entrypoint matches the project's
	#workaround https://github.com/angr/angr/blame/master/angr/exploration_techniques/tracer.py#L74
	#	raise AngrTracerError("Could not identify program entry point in trace!")
	difference = runner.trace[0]-proj.entry
	logger.info("Detected difference of %x", difference)
	for i, e in enumerate(runner.trace):
		runner.trace[i] -= difference
	return (runner.trace, runner.magic, runner.crash_mode, runner.crash_addr)

def tracer_linux(p, stdin):
	#Function taken from: https://github.com/angr/angr/blob/master/tests/test_tracer.py#L26
	trace, _, crash_mode, crash_addr = do_trace(p, stdin, ld_linux=p.loader.linux_loader_object.binary, library_path=set(os.path.dirname(obj.binary) for obj in p.loader.all_elf_objects), record_stdout=True)
	s = p.factory.full_init_state(mode='tracing', stdin=angr.SimFileStream)
	s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

	simgr = p.factory.simulation_manager(s, hierarchy=False, save_unconstrained=crash_mode)
	t = angr.exploration_techniques.Tracer(trace)
	simgr.use_technique(t)
	simgr.use_technique(angr.exploration_techniques.Oppologist())

	return simgr, t

def main():
	base_path = "/job/target/"
	ld_path  = base_path+"lib"
	#inputs: CMD, input stream, input testcase filename
	CMD = [base_path+"CGC_Hangman_Game"]
	input_testcase = base_path+"corpus/0"

	#read testcase
	with open(input_testcase, "rb") as f:
		input_data = f.read()
	#load the binary with the specified libraries
	p = angr.Project(CMD[0], except_missing_libs=True, 
							 ld_path=(ld_path))

	logging.getLogger("angr.exploration_techniques.driller_core").setLevel('DEBUG')
	#https://github.com/angr/angr/blob/master/tests/test_driller_core.py#L28
	simgr, t = tracer_linux(p, input_data)
	d = angr.exploration_techniques.DrillerCore(t._trace)
	simgr.use_technique(d)

	hook(locals())
	#Fails to run simgr.run()


if __name__ == '__main__':
	main()