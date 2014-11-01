import os, glob, sys, pickle, struct, collections

#Directory
BENCHMARKS = "BENCHMARKS/" # The directory of our benchmarks
ARM = "ARM/" # The ARM executables of these benchmarks
NM = "NM/" # The directory of nm files
OBJDUMP = "OBJDUMP/" # The directory of  objdump files
DOT = "DOT/" # The directory of dot files
RESULT = "RESULT/" # The directory of inlined-CFG results in a curtain data format
PDF = "PDF/" # the directory of visulaized inlined-CFGs

#Parameters
ARM_PREFIX = "arm-none-linux-gnueabi-"
LDFLAGS = '-lm -lstdc++ -lgcc'


#Execute command
def csystem(name):
    print name
    rc = os.system(name)
    if rc != 0:
        print 'system call failed: %s' % name
        sys.exit(1) 

def build(program):
	csystem("arm-none-linux-gnueabi-gcc -static -o %s.elf %s %s" % (ARM+program, BENCHMARKS+program, LDFLAGS))
	csystem("arm-none-linux-gnueabi-nm -aS %s.elf > %s.nm" % (ARM+program, NM+program))
	csystem("arm-none-linux-gnueabi-objdump -d %s.elf > %s.od" % (ARM+program, OBJDUMP+program))

def GenerateInlinedCFG(nm_file,ob_file):
	csystem("python GenerateInlinedCFG %s %s %s %s" % (nm_file, ob_file, DOT, RESULT))

def GeneratePDF(dot_file, pdf_file):
	csystem("dot -Tpdf %s -o %s" % (dot_file, pdf_file))

if __name__ == "__main__":
	for program in os.listdir(BENCHMARKS):
		build(program)
		#GenerateInlinedCFG(NM+program+".nm", OBJDUMP+program+".ob")
		#GeneratePDF(DOT+program+".dot", PDF+program+".pdf")

