from bs4 import BeautifulSoup
import requests
import html
import csv

class CVEPuller():
	def __init__(self):
		self.nvd_cve= None
		self.nvd_html= None
		self.cvss2_score=""
		self.cvss3_score=""

	# Method to read the National Vulnerability Database
	def read_nvd(self,input_CVE):
		self.nvd_cve=requests.get(f"https://nvd.nist.gov/vuln/detail/{str(input_CVE)}")
		self.nvd_html=BeautifulSoup(self.nvd_cve.text, 'html.parser')
		return self.nvd_html

	# Method to read an input CSV file
	def read_csv(self,input_csv,desc,date):
		with open(input_csv, newline='') as file:
			r=csv.reader(file,delimiter=' ')
			for row in r: 
				print(f"**CVE: {str(row[0])}**")
				print(self.findCVSS2(str(row[0])))
				print(self.findCVSS3(str(row[0])))
				if desc: 
					print(self.findDesc(str(row[0])))
				if date:
					print(self.findDate(str(row[0])))

	# Method to find the CVSS Version 2 Score
	def findCVSS2(self,input_CVE):
		local_nvd=self.read_nvd(input_CVE)
		spans=local_nvd.find_all('span',{'class' : 'severityDetail'})

		if not spans:
			self.cvss2_score="Not a valid CVE"
		elif not spans[-1].find_all(attrs={"data-testid":"vuln-cvss2-panel-score-na"}):
			self.cvss2_score=((spans[-1].find(attrs={"id":'Cvss2CalculatorAnchor'})).string)
		else: 
			self.cvss2_score="No CVSSv2 Score"

		return self.cvss2_score 

	# Method to find the CVSS Version 3 Score
	def findCVSS3(self,input_CVE):
		local_nvd=self.read_nvd(input_CVE)

		spans=local_nvd.find_all('span',{'class' : 'severityDetail'})
		if not spans:
			self.cvss3_score="Not a valid CVE"
		elif not spans[0].find_all(attrs={"data-testid":'vuln-cvss3-panel-score-na'}): # if there is a CVSS V3 
			try: 
				self.cvss3_score=((spans[0].find(attrs={"data-testid":'vuln-cvss3-panel-score'})).string)
			except: 
				self.cvss3_score=((spans[0].find(attrs={"data-testid":'vuln-cvss3-cna-panel-score'})).string)		
		else: 
			self.cvss3_score="No CVSSv3 Score"

		return self.cvss3_score

	# Method to find the CVE Description
	def findDesc(self,input_CVE):
		local_nvd=self.read_nvd(input_CVE)
		return (local_nvd.find(attrs={"data-testid":'vuln-description'}).string)
	
	# Method to find the date of the CVE 
	def findDate(self,input_CVE):
		local_nvd=self.read_nvd(input_CVE)
		return (local_nvd.find(attrs={"data-testid":'vuln-published-on'}).string)





