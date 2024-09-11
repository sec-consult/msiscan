#!/bin/python
# Author: Michael Baer <michael.baer@sec-consult.com>

import os
import csv
import sys
import json
from termcolor import colored, cprint
import subprocess
import sqlite3
import re
import argparse
import string
import random
from enum import Enum
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

print_info = lambda x : cprint(x, "white")

parser = argparse.ArgumentParser(
	prog='msiscan.py',
	description='Analyzes msi installer to detect vulnerable ones'
	)
parser.add_argument('--show-all', action='store_true', help='Show all custom actions. Otherwise only elevated actions.')
parser.add_argument('--with-result', action='store_true', help='Store the results in a json file. You don\'t need this usually.')
parser.add_argument('filename', help='msi Installer to be analyzed')

args = parser.parse_args()

with open(f"{SCRIPT_DIR}/msi_data.json") as inf:
	msidata = json.load(inf)

def rndString(n):
	return "".join(random.choice(string.ascii_lowercase) for _ in range(n))

def parse_msql_string(s):
	tokens = []
	in_string = False
	is_escape = False
	for c in s:
		if is_escape:
			if c == "'":
				tokens.append("--SINGLEQUOTE--")
			elif c == "\\":
				tokens.append("--BACKSLASH--")
			elif c == "r":
				tokens.append("--CR--")
			elif c == "n":
				tokens.append("--NL--")
			else:
				print(f"Unknown escape sequence \\{c}")
				sys.exit(1)
			is_escape = False
		else:
			if c == "'":
				if in_string:
					tokens.append("--ENDSTRING--")
					in_string = False
				else:
					tokens.append("--STARTSTRING--")
					in_string = True
			elif c == "\\":
				is_escape = True
			else:
				tokens.append(c)
	if is_escape:
		print(f"Error: Escapesequence at end of string")
		sys.exit(1)
	if in_string:
		printf("Error: Unterminated string")
		sys.exit(1)
	return tokens

def write_sqlite_string(tokens):
	res = ""
	TOKEN = {
		"--STARTSTRING--": "'",
		"--ENDSTRING--": "'",
		"--BACKSLASH--": "\\\\",
		"--SINGLEQUOTE--": "''",
		"--CR--": "\\r",
		"--NL--": "\\n"
	}
	for t in tokens:
		if t in TOKEN:
			res += TOKEN[t]
		else:
			res += t
	return res

def convert_mysql_to_sqlite(d):
	ts = parse_msql_string(d)
	d = write_sqlite_string(ts)

	d = d.replace("`", "\"").replace("CHAR(72)", "TEXT").replace("LOCALIZABLE", "")
	# sourround PRIMARY KEY parameter
	d = re.sub("PRIMARY KEY ([^)]+)", r",PRIMARY KEY(\1)", d)
	with open("/tmp/sql.tmp", "w") as outf:
		outf.write(d)
	sql = run_external([SCRIPT_DIR + "/mysql2sqlite.sh", "/tmp/sql.tmp"])
	return sql

def parse_filetype(ft):
	if "executable (GUI)" in ft:
		return "GUI"
	if "executable (console)" in ft:
		return "Console"
	print_info(f"Filetype {ft} unknown")
	return "Unknown"

def run_external(cmd, decode=True):
	res = subprocess.check_output(cmd)
	if decode:
		return res.decode()
	return res

TABLES = {
	"CustomAction" : 'CREATE TABLE "CustomAction" ("Action" TEXT NOT NULL, "Type" INT NOT NULL, "Source" TEXT, "Target" CHAR(255), "ExtendedType" LONG ,PRIMARY KEY("Action"))',
	"File": 'CREATE TABLE "File" ("File" TEXT NOT NULL, "Component_" TEXT NOT NULL, "FileName" CHAR(255) NOT NULL , "FileSize" LONG NOT NULL, "Version" TEXT, "Language" CHAR(20), "Attributes" INT, "Sequence" LONG NOT NULL ,PRIMARY KEY("File"))',
	"InstallUISequence": 'CREATE TABLE "InstallUISequence" ("Action" TEXT NOT NULL, "Condition" CHAR(255), "Sequence" INT ,PRIMARY KEY("Action"))',
	"InstallExecuteSequence": 'CREATE TABLE "InstallExecuteSequence" ("Action" TEXT NOT NULL, "Condition" CHAR(255), "Sequence" INT ,PRIMARY KEY("Action"))',
	"Binary": 'CREATE TABLE "Binary" ("Binary" TEXT, "Data" TEXT)',
	"Property": 'CREATE TABLE "Property" ("Property" TEXT, "Value" TEXT)',
	"Directory": 'CREATE TABLE "Directory" ("Directory" TEXT, "Directory_Parent" TEXT, "DefaultDir" TEXT)',
	"CreateFolder": 'CREATE TABLE "CreateFolder" ("Directory_" TEXT, "Component_" TEXT)',
	"MsiLockPermissionsEx": 'CREATE TABLE "MsiLockPermissionsEx" ("MsiLockPermissionsEx" TEXT, "LockObject" TEXT, "Table" TEXT, "SDDLText" TEXT, "Condition" TEXT)'
}

class Rating(Enum):
	UNKNOWN = 0
	NONE = 1
	UNLIKELY = 2
	LIKELY = 3
	VERYLIKELY = 4

class InvestigateDifficulty(Enum):
	NONE = 0    # not specified
	EASY = 1    # easy, attack path known
	MEDIUM = 2  # scripts etc.
	HARD = 3    # binaries involved

class MSI:
	def __init__(self, msi):
		self.actions = [] # list of actions
		self.db = sqlite3.connect(':memory:')
		self.db.row_factory = sqlite3.Row
		self.msi = msi
		self.tables = run_external(["msiinfo", "tables", self.msi]).splitlines()
		for t in TABLES:
			if t in self.tables:
				if self.parse_table(t) == False:
					self.db.execute(TABLES[t]) # fallback
			else:
				self.db.execute(TABLES[t])
		self.list_executables()
		self.base_folder = "/tmp/msi_tmp"
		os.makedirs(self.base_folder, exist_ok = True)
		try:
			run_external([
				"msiextract",
				"-C",
				self.base_folder,
				self.msi
			])
		except subprocess.CalledProcessError as e:
			print_info("Failed to extract msi package. Maybe some cab file is missing")
		self.check_repairmode()
		props = self.get_property("SecureCustomProperties")
		if props != None:
			self.secProps = props.split(":")
		else:
			self.secProps = []
		#print(self.secProps)

	def print_meta(self):
		cprint(f"filename\t{self.msi}", "light_grey")
		for x in ["Manufacturer", "ProductName", "ProductVersion", "REINSTALLMODE"]:
			d = self.db.execute(f"SELECT Value FROM Property WHERE Property = '{x}'")
			f = d.fetchall()
			if len(f) > 0:
				cprint(f"{x}\t{f[0]['Value']}", "light_grey")
			else:
				cprint(f"{x}\t-", "light_grey")

	def check_repairmode(self):
		d = self.db.execute("SELECT * FROM Property WHERE Property = 'ARPNOREPAIR'")
		f = d.fetchall()
		if len(f) > 0:
			assert len(f) == 1
			value = f[0]["Value"]
			if value in ["1", "yes"]:
				cprint(f"\tRepairmode disabled (Value: '{value}')", "red")
			elif value in ["0", "no"]:
				pass # not disabled
			else:
				cprint(f"\tRepairmode might be disabled (Value: '{value}')", "yellow")
			self.repairmode = False
		else:
			self.repairmode = True

	def run(self):
		self.analyze_customaction_table()

	def parse_table(self, table):
		try:
			d = run_external(["msiinfo", "export", "-s", self.msi, table])
			d = convert_mysql_to_sqlite(d)
			ds = d.splitlines()
			for dds in ds:
				res = self.db.execute(dds)
			return True
		except subprocess.CalledProcessError:
			print_info(f"Failed reading table {table}. Using empty fallback.")
			return False
	
	def list_executables(self):
		self.files = run_external([
			"msiextract",
			"-l",
			self.msi
			]).splitlines()

	def get_file_name(self, fid):
		f = self.db.execute("SELECT FileName FROM File WHERE File = ?", (fid,))
		fs = f.fetchall()
		if len(fs) != 1:
			return "??"
		fr = fs[0]
		if "|" in fr["FileName"]:
			fs = fr["FileName"].split("|")
			return fs[1]
		else:
			return fr["FileName"]
	
	# returns the name of the binary (can be a script as well)
	def get_binary_name(self, bid):
		return f"Binary.{bid}" # TODO: better parse Binary.idt

	def analyze_sequences(self):
		s = self.db.execute("SELECT * FROM InstallUISequence ORDER BY Sequence ASC")
		print("--- Sequence ---")
		for ac in s:
			if int(ac['Sequence']) < 0:
				pass # error stuff
			else:
				x, color = standard_action.analyze_standard_action(ac['Action'], ac['Condition'])
				if x:
					cprint(f"\t{x}", color)
	
	def resolve_dirpath(self, dir_id):
		path = ""# dir_id
		while True:
			d = self.db.execute("SELECT * FROM Directory WHERE Directory = ?", (dir_id,))
			d = d.fetchall()[0]
			x = d['DefaultDir']
			if "|" in x:
				x = x[x.find("|")+1:]
			path = f"{x}\\{path}"
			dir_id = d["Directory_Parent"]
			if d["Directory_Parent"] == None:
				break
		return path

	def get_property(self, prop):
		d = self.db.execute("SELECT Value FROM Property WHERE Property = ?", (prop,))
		ds = d.fetchall()
		if len(ds) == 1:
			return ds[0]["Value"]
		return None

	def resolve_formatted(self, value):
		oldvalue = None
		while oldvalue != value:
			oldvalue = value
			m = re.search("\\[#([a-zA-Z0-9\\.]+)\\]", value)
			if m:
				resolved = self.get_file_name(m.group(1))
				value = value.replace(m.group(0), resolved)
		return value

	"""
		Analyzes the command string for potential issues
	"""
	def analyze_command(self, cmd, infos, cmd_includes_params = True):
		if cmd_includes_params:
			if cmd[0] == '"':
				binary = cmd[1:cmd.find('"', 1)]
			else:
				parts = cmd.split(" ")
				binary = parts[0]
		else:
			binary = cmd
		binary = binary.lower() # lowercase to normalize
		if "." not in binary: # append exe if not supplied
			binary += ".exe"
		if binary.startswith("[systemfolder]"):
			binary = binary[14:]
		elif binary.startswith("[system64folder]"):
			binary = binary[16:]
			
		if "powershell.exe" in binary:
			rating = Rating.UNKNOWN
			diff = InvestigateDifficulty.MEDIUM # Script Code
			infos.append(f"Command: {cmd}")
			if "-NoProfile" in cmd:
				infos.append("PowerShell: -NoProfile is set (safe)")
			else:
				infos.append("PowerShell: -NoProfile missing (vulnerable)")
				rating = Rating.VERYLIKELY
				diff = InvestigateDifficulty.EASY
			return rating, diff
		if binary in msidata["binaries"]:
			md = msidata["binaries"][binary]
			if md["type"] == "console":
				infos.append("VULNERABLE to conhost window because it opens console application.")
				if "conhost_lockfile" in md:
					infos.append(f"Exploit: while($true) {{ .\\SetOpLock.exe '{md['conhost_lockfile']}' x }}")
				else:
					infos.append(f"Exploit: Find a file that is access by the binary (ProcMon) and use SetOpLock to lock it") # TODO suggest one
				infos.append(f"Command\t{cmd}")
				rating = Rating.VERYLIKELY
				diff = InvestigateDifficulty.EASY # Procmon
			else:
				infos.append("Investigate: Any unsafe action performed by the executable?")
				rating = Rating.UNKNOWN
				diff = InvestigateDifficulty.HARD
			return rating, diff
		else: # Unknown, probably installed
			c = re.search("([a-zA-Z0-9_\\-\\.]+.exe)", cmd) # just get the filename
			if c == None:
				infos.append("No idea where this binary comes from.")
				infos.append("Easy check: Locate it and check the filetype if it is Console (Vulnerable) or GUI (safe)")
				infos.append(f"Executable: {cmd}")
				return Rating.UNKNOWN, InvestigateDifficulty.HARD # don't know about it
			else:
				path = run_external(["find", self.base_folder, "-iname", c.group(1)]).strip()
				if len(path) == 0:
					infos.append(f"Cannot find binary {cmd}")
					return Rating.UNKNOWN, InvestigateDifficulty.HARD
				paths = path.splitlines()
				return self.analyze_exe(paths[0], cmd, infos)

	def analyze_exe(self, exe, command, infos):
		filetype = run_external([
			"file",
			exe
			])
		filetype = parse_filetype(filetype)
		if filetype == "Console":
			infos.append("VULNERABLE to conhost window because it opens console application.")
			infos.append(f"Exploit: Find a file that is access by the binary (ProcMon) and use SetOpLock to lock it")
			infos.append(f"Command\t{command}")
			rating = Rating.VERYLIKELY
			diff = InvestigateDifficulty.EASY # Procmon
		elif filetype == "GUI":
			infos.append("Programtype: EXE (GUI)")
			infos.append("Investigate: Any unsafe action performed by the executable?")
			infos.append(f"Command\t{command}")
			rating = Rating.UNKNOWN
			diff = InvestigateDifficulty.HARD
		else:
			infos.append(f"Unknown filetype executed")
			infos.append(f"Command\t{command}")
			rating = Rating.UNKNOWN
			diff = InvestigateDifficulty.HARD
		return rating, diff
	
	def analyze_script(self, script, function, infos):
		infos.append(f"Code\t{script}")
		infos.append(f"Function\t{function}")
		infos.append("Investigate: Review Script Code for unsafe operations")
		infos.append(f"Obtain Code to analyze: msiinfo extract <MSI> Binary.{script}")
		rating = Rating.UNKNOWN
		diff = InvestigateDifficulty.MEDIUM
		return rating, diff

	def analyze_customaction_table(self):
		actions = self.db.execute("SELECT * FROM CustomAction")
		for action in actions:
			name = action["Action"]
			typ = action["Type"]
			source = action["Source"]
			target = action["Target"]
			
			is_system = False
			is_hidden = False # hidden from logs etc.?
			is_64bit = False

			type_str = ""
			infos = []

			# https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options
			if typ & (64 + 128) == (64 + 128):
				# async continues after finishing
				typ -= 192
			if typ & 64 != 0:
				# synchron, ignore exit code
				typ -= 64
			if typ & 128 != 0:
				# asynchron, wait at end of sequence
				typ -= 128
			# https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-execution-scheduling-options
			if typ & 768 == 768:
				# complex running
				typ -= 768
			if typ & 256 == 256:
				# do not run more than once
				typ -= 256
			if typ & 512 == 512:
				# run once per process
				typ -= 512
			# https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options
			if typ & 1024 == 1024:
				# queue
				typ -= 1024
			if typ & 2048 == 2048:
				# run as SYSTEM
				typ -= 2048
				is_system = True
			if typ & 4096 == 4096:
				is_64bit = True
				typ -= 4096
			# https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-hidden-target-option
			if typ & 8192 == 8192:
				typ -= 8192
				is_hidden = True
			
			rating = Rating.UNKNOWN
			diff = InvestigateDifficulty.NONE
			
			# https://learn.microsoft.com/en-us/windows/win32/msi/summary-list-of-all-custom-action-types
			x = ""
			""" NOT correct
				Bit 0: DLL vs EXE, JS vs. VB
				Bit 1: Binary <-> Script			
			
				DLL : + 0
				EXE : + 1
				JS  : + 4
				VB  : + 5
				
				BinaryData/Stream: 1
			"""
			if typ == 1: # ? (DLL) + ? (BinaryData)
				type_str = f"DLL (taken from installer)"
				if source.startswith("Wix"): # wix library. we assume it to be safe, except some special functions
					if target == "WixShellExec":
						infos.append(f"Opens content of Property 'WixShellExecTarget'")
						p = self.get_property('WixShellExecTarget')
						infos.append(f"Defaultvalue: {p}")
						if p != None:
							resolved = self.resolve_formatted(p)
							infos.append(f"Resolved: {resolved}")
							rating, diff = self.analyze_command(resolved, infos, cmd_includes_params = False)
						else:
							infos.append(f"No default value, cannot find the binary")
							rating = Rating.UNKNOWN
							diff = InvestigateDifficulty.HARD
					elif "RemoveFolderEx" in target:
						cprint(f"{target} - maybe vulnerable to CVE-2024-29188", "yellow")
					#elif "GetTempPath" in target:
					#	cprint(target, "yellow")
					else:
						infos.append(f"From WiX library ({source}:{target})")
						rating = Rating.UNLIKELY
				else:
					infos.append(f"BinaryTable\t{source}")
					infos.append(f"EntryPoint\t{target}")
					rating = Rating.UNKNOWN
				diff = InvestigateDifficulty.HARD # binary reversing
			elif typ == 2: # ? (EXE) + ? (BinaryData)
				type_str = f"EXE (taken from installer)"
				fb = "Binary." + source
				binary = run_external([
					"msiinfo",
					"extract",
					self.msi,
					fb
					], decode=False)
				with open(self.base_folder + "/tmpfile", "wb") as outf:
					outf.write(binary)
				rating, diff = self.analyze_exe(self.base_folder + "/tmpfile", fb, infos)
			elif typ == 5: # ? (JS) + ? (BinaryData), this can have is_64bit flag
				type_str = f"JS (taken from installer)"
				script = self.get_binary_name(source)
				rating, diff = self.analyze_script(source, target, infos)
			elif typ == 6: # ? (VB) + ? (BinaryData), this can have is_64bit flag
				type_str = f"VB (taken from installer)"
				script = self.get_binary_name(source)
				rating, diff = self.analyze_script(source, target, infos)
				rating = Rating.UNKNOWN
				diff = InvestigateDifficulty.MEDIUM
			elif typ == 17: # (DLL) + SourceFile
				type_str = "DLL (installed)"
				dll = self.get_file_name(source) # key to FileTable
				infos.append(f"Code\t{dll}")
				infos.append(f"Function\t{target}")
				diff = InvestigateDifficulty.HARD # binary reversing
			elif typ == 18: # 2(exe) + 16 (SourceFile)
				# Executable from installed
				type_str = f"EXE (installed)"
				exe = self.get_file_name(source) # key to FileTable
				matches = list(filter(lambda x: x.endswith(exe), self.files))
				targetstr = target if target else ""
				if len(matches) == 0:
					rating = Rating.UNKNOWN
					diff = InvestigateDifficulty.HARD
					infos.append(f"Could not find the executable {source}")
				else:
					rating, diff = self.analyze_exe(self.base_folder + "/" + matches[0], matches[0] + " " + targetstr, infos)
			elif typ == 19:
				type_str = f"Shows Error Message"
				infos.append(f"{target}")
				rating = Rating.NONE
			elif typ == 21:
				type_str = f"JS (installed)"
				rating, diff = self.analyze_script(source, target, infos)
			elif typ == 22:
				type_str = f"VB (installed)"
				rating, diff = self.analyze_script(source, target, infos)
			elif typ == 34: # 2(exe) + 32 (msidbCustomActionTypeDirectory)
				type_str = f"EXE (commandline)" # not necessarily exe, but also scriptfiles etc.
				wd = self.resolve_dirpath(source)
				infos.append(f"Workdir\t'{wd}'")
				rating, diff = self.analyze_command(target, infos, cmd_includes_params = True)
			elif typ == 35:
				type_str = "Change Install Directory"
				directory = self.resolve_dirpath(source)
				infos.append(f"Directory\t{directory}")
				infos.append(f"Unknown\t{target}")
			elif typ == 37:
				type_str = f"JS (embedded)"
				infos.append("-- Code --")
				code = target.splitlines()
				infos += code
				infos.append("-- Code Ende --")
				rating = Rating.UNKNOWN
				diff = InvestigateDifficulty.EASY # probably short code
			elif typ == 38:
				type_str = f"VB (embedded)"
				if "WScript.Shell" in target:
					rating = Rating.LIKELY
					self.new_flag = True
				else:
					rating = Rating.UNKNOWN
				infos.append("-- Code --")
				code = target.replace("\\n", "\n").replace("\\r", "\r")
				infos += [code]
				infos.append("-- Code Ende --")
				diff = InvestigateDifficulty.EASY # probably short code
			elif typ == 50: # 2(exe) + 48 (msidbCustomActionTypeProperty)
				type_str = f"EXE path by property"
				rating, diff = self.analyze_command(source, infos, cmd_includes_params = False)
				infos.append(f"Params\t{target}")
			elif typ == 51:
				type_str = "Set Property"
				infos.append(f"{source} := {target}")
				rating = Rating.NONE
				diff = InvestigateDifficulty.NONE
			elif typ == 53:
				type_str = f"JS (by property)"
				infos.append(f"Code\t{source}")
				infos.append(f"Function\t{source}")
				rating = Rating.UNKNOWN
				diff = InvestigateDifficulty.EASY # probably short code
			elif typ == 54:
				type_str = f"VB (by property)"
				infos.append(f"Code\t{source}")
				infos.append(f"Function\t{source}")
				rating = Rating.UNKNOWN
				diff = InvestigateDifficulty.EASY # probably short code
			else:
				type_str = f"ERROR: Type {typ} in {name} unknown"
				typ = typ & 63 # only use last bits
				
			verdict = f"{str(rating)} | {str(diff)}  {is_system}"
			text = f"{type_str} [{name=}] {verdict}"
			if len(infos) > 0:
				text += "\n\t" + "\n\t".join(infos)
			
			colors = {
				Rating.NONE: "white",
				Rating.UNKNOWN: "cyan",
				Rating.UNLIKELY: "blue",
				Rating.LIKELY: "yellow",
				Rating.VERYLIKELY: "red",
			}
			if (not is_system or rating == Rating.NONE) and not args.show_all:
				shown = False
			else:
				cprint(text, colors[rating])
				shown = True
			
			# check where this action is invoked from
			if shown:
				inv = self.db.execute("SELECT * FROM InstallUISequence WHERE Action = ? UNION SELECT * FROM InstallExecuteSequence WHERE Action = ?", (name, name))
				invs = list(inv.fetchall())
				if len(invs) == 0:
					cprint("\tAction never used", "light_green")
				elif len(invs) > 1:
					cprint("\tAction used multiple times", "light_green")
				else:
					cond = invs[0]['Condition']
					if cond != None:
						cprint(f"\tAction only invoked upon: {cond}", "light_green")
			
			self.actions.append({
				"rating": str(rating),
				"diff": str(diff),
				"is_system": is_system,
				"type": typ,
				"type_str": type_str,
				"infos": infos
			})

	def subinstaller(self):
		d = run_external(["msiinfo", "streams", self.msi])
		ds = d.splitlines()
		c = 0
		for stream in ds:
			if stream.endswith(".msi"):
				print_info("-" * 30)
				print_info(f"Found Sub-Installer {stream}")
				subinst = run_external(["msiinfo", "extract", self.msi, stream], decode=False)
				r = rndString(8)
				subname = f"/tmp/submsi{r}.msi"
				with open(subname, "wb") as outf:
					outf.write(subinst)
				run(subname)

	def repl_formatvars(self, s):
		for p in self.secProps:
			s = s.replace("[" + p + "]", "@@[" + p + "]@@")
		return s
	
	def print_formatstring(self, s, color):
		splitStr = "|".join(f"(?:\\[{x}\\])" for x in self.secProps)
		parts = re.split(f"({splitStr}", s)
		for p in parts:
			cprint(p, color)
			
def run(fn):
	m = MSI(fn)
	m.print_meta()
	m.run()
	import shutil
	shutil.rmtree("/tmp/msi_tmp")

	m.subinstaller()
	return m

# This is not ready to be used yet
def is_vulnerable(m):
	if not m.repairmode:
		return False
	def folders(self):
		print("Folders created. If they are outside [INSTALLDIR] (or './'), you might have write access and can inject stuff")
		f = self.db.execute("SELECT * FROM CreateFolder")
		fr = f.fetchall()[0]
		for folder in fr:
			path = self.resolve_dirpath(fr['Directory_'])
			print(f"{path}")
		# MsiLockPermissionsEx
		f = self.db.execute("SELECT * FROM MsiLockPermissionsEx")
		# TODO: also LockPermissions
		fr = f.fetchall()
		
		for p in fr:
			if p["Table"] == "CreateFolder":
				path = self.resolve_dirpath(p["LockObject"])
				#print(f"{path}\t{p['SDDLText']}")
				s = Sddl.from_string(p["SDDLText"], "directory")
				for al in s.ace_list:
					string = al.trustee
					#al.pretty_print(verbose=False, indent=' '*4)
					if al.trustee in ["Administrators", "Local System"]:
						pass # we don't care about those
					else:
						print(al.ace_type)
						if al.ace_type:
							string += " " + al.ace_type
						if al.permissions:
							perm_strings = []
							for perm in al.permissions:
								for perm2 in perm.permissions:
									perm_strings.append(str(perm2))
							string += " " + " | ".join(perm_strings)
						print(f"{path} {string}")
			else:
				print(f"Permission {p['Table']} not implemented")

	for a in m.actions:
		if a["is_system"] and a["rating"] == Rating.VERYLIKELY:
			return True
	return False

fn = args.filename
if args.with_result:
	VERSION = 7
	with open("apps_infos.json") as inf:
		j = json.load(inf)

	if fn not in j:
		j[fn] = {
			"lastVersion" : 0,
			"vuln": False,
			"repairmode": False,
			"actions": None
		}
	elif j[fn]["lastVersion"] == VERSION:
		print("Already run")
		sys.exit(0)

m = run(args.filename)
#m.folders()
if args.with_result:
	j[fn]["lastVersion"] = VERSION
	j[fn]["repairmode"] = m.repairmode
	j[fn]["actions"] = m.actions
	with open("apps_infos.json", "w") as outf:
		json.dump(j, outf, indent="\t")

