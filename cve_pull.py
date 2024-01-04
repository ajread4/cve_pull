import argparse
from bin.pull import CVEPuller

def main():
	"""
	Main function for cve_pull
	"""
	parser = argparse.ArgumentParser(description='cve_pull - a tool to pull information regarding a CVE or multiple CVEs from the National Vulnerability Database (NVD).')
	parser.add_argument('-c ', '--cve', action='store', help='specify the CVE # as CVE-####-#####',metavar='cve')
	parser.add_argument('-f ', '--file', action='store', help='specify a CSV with multiple CVE #s in a single column',metavar='cve_file')
	parser.add_argument("-d","--description", help="return the description of the CVE",action="store_true")
	parser.add_argument("-t","--date", help="return the NVD published date",action="store_true")

	# Parse the Arguments 
	args=parser.parse_args()

	# Instantiate the Class 
	cve_pull=CVEPuller() 

	# If only one CVE is requested by the user
	if (args.cve):
		print(f'CVSS2 Score: {cve_pull.findCVSS2(args.cve)}')
		print(f'CVSS3 Score: {cve_pull.findCVSS3(args.cve)}')

		# If the user wants a description of the CVE
		if args.description:
			print(f'Description: {str(cve_pull.findDesc(args.cve))}')
		if args.date:
			print(f'NVD Published Date: {str(cve_pull.findDate(args.cve))}')

	# If the CVEs are in a file
	if (args.file):
		cve_pull.read_csv(args.file,args.description,args.date)

if __name__=="__main__":
	try:
		main()
	except Exception as err:
		print(repr(err))