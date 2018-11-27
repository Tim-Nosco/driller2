import angr, claripy
import logging

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)
logger = logging.getLogger('executor.py')


def main():
	base_path = "/job/target/"
	bin_path = base_path+"CGC_Hangman_Game"
	ld_path = base_path+"lib"
	p = angr.Project(bin_path,
		except_missing_libs=True,
		custom_ld_path=ld_path)


if __name__ == '__main__':
	main()