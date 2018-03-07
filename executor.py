import angr
import claripy
import monkeyhex

MAXLEN = 30

def scase(s):
	s = s[:MAXLEN]
	print "NEW TESTCASE:\n{}".format(s)
	print "ENCODED:\n{}".format(s.encode('hex'))

def check_sat(state,testcase):
	stdin = state.posix.files[0]
	pos = stdin.pos
	stdin.seek(0)
	cond = map(lambda x: stdin.read_from(1)==x,
		testcase) if testcase else []
	stdin.seek(pos)
	try:
		state.solver.eval(stdin.all_bytes(), 
			extra_constraints=cond,
			cast_to=str)
		return True
	except angr.errors.SimUnsatError:
		scase(state.solver.eval(stdin.all_bytes(),
			cast_to=str))
		return False

"hangman/root/home/fas/cb-multios/build/challenges/CGC_Hangman_Game/CGC_Hangman_Game"
"hangman/root/lib/i386-linux-gnu/"


if __name__ == "__main__":
	import sys
	assert(len(sys.argv)>=4)
	binary_name = sys.argv[1]
	ld_path = sys.argv[2]
	testcase_file = sys.argv[3]

	with open(testcase_file, 'rb') as f:
		testcase = f.read()

	p = angr.Project(binary_name,
		except_missing_libs=True,
		custom_ld_path=ld_path)

	state = p.factory.full_init_state(add_options=angr.options.unicorn)
	state.posix.files[0].length=MAXLEN

	scase(testcase)
	while True:
		succ = state.step()
		if len(succ.successors)==2:
			state1, state2 = succ.successors
			valid1= check_sat(state1, testcase)
			valid2= check_sat(state2, testcase)
			if valid1 ^ valid2:
				state = state1 if valid1 else state2
			else:
				break
		elif len(succ.successors):
			state = succ.successors[0]
		else:
			break

	print "done."