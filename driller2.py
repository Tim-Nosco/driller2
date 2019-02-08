import argparse, logging, os, shlex
import executor

logger = logging.getLogger(name=__name__)

def _set_log_level(level):
	#interpret specified level
	if not hasattr(logging,level):
		logger.error("Invalid log level specified: %s", level)
		logger.error("Using INFO.")
		level = "INFO"
	#set the level
	logger.setLevel(getattr(logging,level))

if __name__ == '__main__':
	logger = logging.getLogger()
	others = ["angr", "ana", "cle", "claripy"]
	for o in others:
		logging.getLogger(o).setLevel(logging.WARNING)

	parser = argparse.ArgumentParser('executor.py', 
		description="Concollic executor emulating driller.")

	parser.add_argument("-v", default="INFO", 
		help="Set the log level.", dest="level",
		choices=["DEBUG","INFO","WARNING","ERROR","CRITICAL"])
	
	parser.add_argument("-l", help="LD_LIBRARY_PATH. "
		"If the program requires libraries, specify where angr "
		"can find them. Use : to separate entries. "
		"(ex. -l /lib:/usr/lib).", default="", dest="ld_path")
	
	parser.add_argument("-i", required=True, help="Input folder. "
		"Specify the AFL queue format folder to read testcases. "
		"Testcases must be of the format \"id:\d{6}.*\"", 
		dest="input_folder")
	
	parser.add_argument("-o", dest="corpus", default="/dev/shm/corpus",
		help="Output folder. This is the location driller will "
		"create a queue folder of outputs in the same format "
		"as the AFL queue folder.")
	
	parser.add_argument("-f", default="___AUTO___", dest="instream",
		help="Input stream. From what location does the program "
		"under test read? Valid options are a file name, ___FILE___, "
		"___STDIN___, or (default) ___AUTO___ which will use "
		"___FILE___ if specified in the command, if not specified, "
		"it will use ___STDIN___.")

	parser.add_argument("command", nargs=argparse.REMAINDER,
		help="Specify the command to run where argv[0] is the "
		"target binary and argv[1:] are passed to said binary. "
		"Use ___FILE___ to specify an input data stream file.")

	args=parser.parse_args()

	_set_log_level(args.level)

	try:
		logger.debug("Creating output directory: %s", args.corpus)
		os.mkdir(args.corpus)
	except FileExistsError as e:
		logger.warning("Corpus folder already exists")

	ld_var = args.ld_path.split(":")
	logger.debug("Processed LD_LIBRARY_PATH=%s", ld_var)

	if args.instream != "___AUTO___":
		#its a static filename
		instream = args.instream
	elif "___FILE___" in args.command:
		#its a mutating filename
		instream = "___FILE___"
	else:
		#its stdin
		instream = "___STDIN___"
	logger.debug("Detected input stream: %s", instream)

	#TODO start afl node, respect instream

	#maybe this isn't required? 
	#for each testcase in queue folder, run executor.main
	regression_tests = []
	for p in os.listdir(args.input_folder):
		p = os.path.join(args.input_folder, p)
		if os.path.isfile(p):
			regression_tests.append(p)

	#TODO loop
	logger.debug("Patching command: %s", args.command)
	command = shlex.split(' '.join(args.command)
		.replace("___FILE___", instream))
	logger.debug("Post patch: %s", command)
	executor.main(
		command, 
		args.corpus, 
		regression_tests[0],
		ld_var,
		instream
	)