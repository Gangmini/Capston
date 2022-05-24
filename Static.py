#-*- coding: utf-8 -*-

from __future__ import division
from tools.modified.androguard.core.bytecodes import apk
from tools.modified.androguard.core.bytecodes import dvm
from tools.modified.androguard.core.analysis import analysis
from tools.modified.androguard.core import bytecode
import uuid
import os
import re
import time
from datetime import datetime
import hashlib    #sha256 hash
from textwrap import TextWrapper   #for indent in output
import base64
import collections	#for sorting key of dictionary
import traceback
import random
import argparse
from zipfile import BadZipfile
from ConfigParser import SafeConfigParser
import platform
import imp
import sys

"""
	*****************************************************************************
	** AndroBugs Framework - Android App Security Vulnerability Scanner        **
	** This tool is created by Yu-Cheng Lin (a.k.a. AndroBugs) @ AndroBugs.com **
	** Twitter: @AndroBugs                                                     **
	** Email: androbugs.framework@gmail.com                                    **
	*****************************************************************************

	** Read Python codeing style first: http://www.python.org/dev/peps/pep-0008/ **

	1.This script run under Python 2.7. DO NOT use Python 3.x

	2.You need to install 'chilkat' component version in accordance with Python 2.7 first. This is for certificate checking.
	  See the explanation of function 'def get_certificate(self, filename)' in 'apk.py' file
	  => It becomes optional now. Since the related code is not comment out for ease of use and install.

	3.Use command 'grep -nFr "#Added by AndroBugs" *' to see what AndroBugs Framework has added to Androguard Open Source project under "tools/modified/androguard" root directory.

	4.Notice the "encoding" when copy and paste into this file (For example: the difference between single quote ' ).

	5.** Notice: In AndroidManifest.xml => The value "TRUE" or "True" or "true" are all the same (e.g. [android:exported="TRUE"] equals to [android:exported="true"]). 
	  So if you want to check whether it is true, you should MAKE IT LOWER first. Otherwise, your code may have security issues. **

	Read these docs first:
		1.http://s.android.com/tech/dalvik/dex-format.html
		2.http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

	Provide the user the options:
		1.Specify the excluded package name (ex: Facebook.com, Parse.com) and put it into "STR_REGEXP_TYPE_EXCLUDE_CLASSES"
		2.Show the "HTTP Connection" related code or not
		3.Show the "KeyStore" related code or not

	Flag:
		[Critical] => very critical
		[Warning]  => it's ok and not really need to change
		[Notice]   => For hackers, you should notice.
		[Info]	   => Information

	You can use these functions provided by the FilteringEngine to exclude class packages:
		(1)Filter single class name:
			is_class_name_not_in_exclusion(single_class_name_string)

		(2)Filter a list of class name:
			filter_list_of_classes(class_name_list)

		(3)Filter a list of method name:
			filter_list_of_methods(method_list)

		(4)Filter a list of Path:
			filter_list_of_paths(d, path_list)  #a list of PathP

		(5)Filter a list of Variables: #variables_list example: None or [[('R', 166), 5058]] or [[('R', 8), 5050], [('R', 24), 5046]]
			filter_list_of_variables(d, variables_list)   

		(6)Filter dictionary key classes: (filter the class names in the key)
			(boolean) is_all_of_key_class_in_dict_not_in_exclusion(key)

		(7) ...

	Current self-defined error id:
		 - fail_to_unzip_apk_file
		 - apk_file_name_slash_twodots_error
		 - apk_file_not_exist
		 - package_name_empty
		 - classes_dex_not_in_apk

		 search the corresponding error by using MongoDB criteria " {"analyze_error_id":"[error_id]"} "

	AndroBugs Framework is supported with MongoDB. Add "-s" argument if you want all the analysis results to be stored into the MongoDB.
	Please check the "androbugs-db.cfg" file for database configuration.

"""

#Fix settings:

TYPE_REPORT_OUTPUT_ONLY_PRINT = "print"
TYPE_REPORT_OUTPUT_ONLY_FILE = "file"
TYPE_REPORT_OUTPUT_PRINT_AND_FILE = "print_and_file"

TYPE_COMPARE_ALL = 1
TYPE_COMPARE_ANY = 2

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"

#AndroidManifest permission protectionLevel constants
PROTECTION_NORMAL = 0   # "normal" or not set
PROTECTION_DANGEROUS = 1
PROTECTION_SIGNATURE = 2
PROTECTION_SIGNATURE_OR_SYSTEM = 3
PROTECTION_MASK_BASE = 15
PROTECTION_FLAG_SYSTEM = 16
PROTECTION_FLAG_DEVELOPMENT = 32
PROTECTION_MASK_FLAGS = 240

LEVEL_CRITICAL = "Critical"
LEVEL_WARNING = "Warning"
LEVEL_NOTICE = "Notice"
LEVEL_INFO = "Info"

LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 160  #100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 160
LINE_MAX_OUTPUT_INDENT = 20
#-----------------------------------------------------------------------------------------------------

#Customized settings:

DEBUG = True
ANALYZE_ENGINE_BUILD_DEFAULT = 1    # Analyze Engine(use only number)

DIRECTORY_APK_FILES = ""  # "APKs/"

REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE  #when compiling to Windows executable, switch to "TYPE_REPORT_OUTPUT_ONLY_FILE"
DIRECTORY_REPORT_OUTPUT = "Reports/"	#Only need to specify when (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_ONLY_FILE) or (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE)
# DIRECTORY_REPORT_OUTPUT = "Massive_Reports/"

#-----------------------------------------------------------------------------------------------------
"""
Package for exclusion:
Lcom/google/
Lcom/aviary/android/
Lcom/parse/
Lcom/facebook/
Lcom/tapjoy/
Lcom/android/
"""

#The exclusion list settings will be loaded into FilteringEngine later
STR_REGEXP_TYPE_EXCLUDE_CLASSES = "^(Landroid/support/|Lcom/actionbarsherlock/|Lorg/apache/)"
ENABLE_EXCLUDE_CLASSES = True

#-----------------------------------------------------------------------------------------------------

class Writer :

	def __init__(self) :
		self.__package_information = {}
		self.__cache_output_detail_stream = []
		self.__output_dict_vector_result_information = {}		# Store the result information (key: tag ; value: information_for_each_vector)
		self.__output_current_tag = ""					#The current vector analyzed

		self.__file_io_result_output_list = []			#Analyze vector result (for more convenient to save in disk)
		self.__file_io_information_output_list = []		#Analyze header result (include package_name, md5, sha1, etc.)

	def simplifyClassPath(self, class_name) :
		if class_name.startswith('L') and class_name.endswith(';') :
			return class_name[1:-1]
		return class_name

	def show_Path(self, vm, path, indention_space_count=0) :
		"""
			Different from analysis.show_Path, this "show_Path" writes to the tmp writer 
		"""

		cm = vm.get_class_manager()

		if isinstance(path, analysis.PathVar):
			dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
			info_var = path.get_var_info()

			self.write("=> %s (0x%x) ---> %s->%s%s" % (info_var,
													path.get_idx(),
													dst_class_name,
													dst_method_name,
													dst_descriptor),
				indention_space_count)

		else :
			if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
				src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
				dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

				self.write("=> %s->%s%s (0x%x) ---> %s->%s%s" % (src_class_name,
																src_method_name,
																src_descriptor,
																path.get_idx(),
																dst_class_name,
																dst_method_name,
																dst_descriptor),
					indention_space_count)

			else :
				src_class_name, src_method_name, src_descriptor =  path.get_src( cm )

				self.write("=> %s->%s%s (0x%x)" % (src_class_name,
												src_method_name,
												src_descriptor,
												path.get_idx()),
					indention_space_count)

	def show_Path_only_source(self, vm, path, indention_space_count=0) :
		cm = vm.get_class_manager()
		src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
		self.write("=> %s->%s%s" % (src_class_name, src_method_name, src_descriptor), indention_space_count)		

	def show_Paths(self, vm, paths, indention_space_count=0) :
		"""
			Show paths of packages
			:param paths: a list of :class:`PathP` objects

			Different from "analysis.show_Paths", this "show_Paths" writes to the tmp writer 
		"""
		for path in paths :
			self.show_Path( vm, path, indention_space_count )

	def show_single_PathVariable(self, vm, path, indention_space_count=0):
		"""
			Different from "analysis.show_single_PathVariable", this "show_single_PathVariable" writes to the tmp writer 

			method[0] : class name
			method[1] : function name
			method[2][0] + method[2][1]) : description
		"""
		access, idx = path[0]
		m_idx = path[1]
		method = vm.get_cm_method(m_idx)

		self.write("=> %s->%s %s" % (method[0], method[1], method[2][0] + method[2][1]),	indention_space_count)

	#Output: stoping

	def startWriter(self, tag, level, summary, title_msg, special_tag=None, cve_number="") :	
		"""
			"tag" is for internal usage
			"level, summary, title_msg, special_tag, cve_number" will be shown to the users
			It will be sorted by the "tag". The result will be sorted by the "tag".

			Notice: the type of "special_tag" is "list"
		"""
		self.completeWriter()
		self.__output_current_tag = tag

		assert ((tag is not None) and (level is not None) and (summary is not None) and (title_msg is not None)), "\"tag\", \"level\", \"summary\", \"title_msg\" should all have it's value."

		if tag not in self.__output_dict_vector_result_information :
			self.__output_dict_vector_result_information[tag] = []

		dict_tmp_information = dict()
		dict_tmp_information["level"] = level
		dict_tmp_information["title"] = title_msg.rstrip('\n')
		dict_tmp_information["summary"] = summary.rstrip('\n')
		dict_tmp_information["count"] = 0
		if special_tag :
			assert isinstance(special_tag, list), "Tag [" + tag + "] : special_tag should be list"
			dict_tmp_information["special_tag"] = special_tag    #Notice: the type of "special_tag" is "list"
		if cve_number :
			assert isinstance(cve_number, basestring), "Tag [" + tag + "] : special_tag should be string"
			dict_tmp_information["cve_number"] = cve_number

		self.__output_dict_vector_result_information[tag] = dict_tmp_information
		
	def get_valid_encoding_utf8_string(self, utf8_string) :
		"""
			unicode-escape: http://stackoverflow.com/questions/4004431/text-with-unicode-escape-sequences-to-unicode-in-python
			Encoding and Decoding:
				http://blog.wahahajk.com/2009/08/unicodedecodeerror-ascii-codec-cant.html
				http://www.evanjones.ca/python-utf8.html
				http://www.jb51.net/article/26543.htm
				http://www.jb51.net/article/17560.htm
		"""
		return utf8_string.decode('unicode-escape').encode('utf8')

	def write(self, detail_msg, indention_space_count=0) :
		self.__cache_output_detail_stream.append(detail_msg + "\n")

	def get_packed_analyzed_results_for_mongodb(self) :
		# For external storage

		analyze_packed_result = self.getInf()

		if analyze_packed_result :
			if self.get_analyze_status() == "success" :
				analyze_packed_result["details"] = self.__output_dict_vector_result_information
			return analyze_packed_result

		return None

	def get_search_enhanced_packed_analyzed_results_for_mongodb(self) :
		# For external storage

		analyze_packed_result = self.getInf()

		if analyze_packed_result :
			if self.get_analyze_status() == "success" :

				prepared_search_enhanced_result = []

				for tag, dict_information in self.__output_dict_vector_result_information.items() :

					search_enhanced_result = dict()

					search_enhanced_result["vector"] = tag
					search_enhanced_result["level"] = dict_information["level"]
					search_enhanced_result["analyze_engine_build"] = analyze_packed_result["analyze_engine_build"]
					search_enhanced_result["analyze_mode"] = analyze_packed_result["analyze_mode"]
					if "analyze_tag" in analyze_packed_result :
						search_enhanced_result["analyze_tag"] = analyze_packed_result["analyze_tag"]
					search_enhanced_result["package_name"] = analyze_packed_result["package_name"]
					if "package_version_code" in analyze_packed_result :
						search_enhanced_result["package_version_code"] = analyze_packed_result["package_version_code"]
					search_enhanced_result["file_sha512"] = analyze_packed_result["file_sha512"]
					search_enhanced_result["signature_unique_analyze"] = analyze_packed_result["signature_unique_analyze"]
					
					prepared_search_enhanced_result.append(search_enhanced_result)

				return prepared_search_enhanced_result

		return None

	def getInf(self, key=None, default_value=None) :
		if key is None :
			return self.__package_information

		if key in self.__package_information :    
			value = self.__package_information[key]
			if (value is None) and (default_value is not None) :    # [Important] if default_value="", the result of the condition is "False"
				return default_value
			return value

		#not found
		if default_value :    # [Important] if default_value="", the result of the condition is "False"
			return default_value

		return None

	def writePlainInf(self, msg) :
		# if DEBUG :
		print(str(msg))
		# [Recorded here]
		self.__file_io_information_output_list.append(str(msg))

	def writeInf(self, key, value, extra_title, extra_print_original_title=False) :
		# if DEBUG :
		if extra_print_original_title :
			print(str(extra_title))
			# [Recorded here]
			self.__file_io_information_output_list.append(str(extra_title))
		else :
			print(extra_title + ": " + str(value))
			# [Recorded here]
			self.__file_io_information_output_list.append(extra_title + ": " + str(value))

		self.__package_information[key] = value

	def writeInf_ForceNoPrint(self, key, value) :
		self.__package_information[key] = value

	def update_analyze_status(self, status) :
		self.writeInf_ForceNoPrint("analyze_status", status)

	def get_analyze_status(self) :
		return self.getInf("analyze_status")

	def get_total_vector_count(self) :
		if self.__output_dict_vector_result_information :
			return len(self.__output_dict_vector_result_information)
		return 0

	def completeWriter(self) :
		# save to DB
		if (self.__cache_output_detail_stream) and (self.__output_current_tag != "") :   
			#This is the preferred way if you know that your variable is a string. If your variable could also be some other type then you should use myString == ""
			
			current_tag = self.__output_current_tag
			# try :
			if current_tag in self.__output_dict_vector_result_information :
				self.__output_dict_vector_result_information[current_tag]["count"] = len(self.__cache_output_detail_stream)

				"""
					Use xxx.encode('string_escape') to avoid translating user code into command
					For example: regex in the code of users' applications may include "\n" but you should escape it.

					I add "str(xxx)" because the "xxx" of xxx.encode should be string but "line" is not string.
					Now the title and detail of the vectors are escaped(\n,...), so you need to use "get_valid_encoding_utf8_string"

					[String Escape Example] 
					http://stackoverflow.com/questions/6867588/how-to-convert-escaped-characters-in-python
					>>> escaped_str = 'One \\\'example\\\''
					>>> print escaped_str.encode('string_escape')
					One \\\'example\\\'
					>>> print escaped_str.decode('string_escape')
					One 'example'
				"""

				output_string = ""
				for line in self.__cache_output_detail_stream :
					output_string = output_string + str(line).encode('string_escape')	# To escape the "\n" shown in the original string inside the APK

				self.__output_dict_vector_result_information[current_tag]["vector_details"] = self.get_valid_encoding_utf8_string(output_string.rstrip(str('\n').encode('string_escape')))
				try :
					self.__output_dict_vector_result_information[current_tag]["title"] = self.get_valid_encoding_utf8_string(self.__output_dict_vector_result_information[current_tag]["title"])
				except KeyError :
					if DEBUG:
						print("[KeyError on \"self.__output_dict_vector_result_information\"]")
					pass


		self.__output_current_tag = ""
		self.__cache_output_detail_stream[:] = []	# Clear the items in the list

	def is_dict_information_has_cve_number(self, dict_information) :
		if dict_information :
			if "cve_number" in dict_information :
				return True
		return False

	def is_dict_information_has_special_tag(self, dict_information) :
		if dict_information :
			if "special_tag" in dict_information :
				if dict_information["special_tag"] :
					return True
		return False

	def __sort_by_level(key, value):
		try :
			level = value[1]["level"]

			if level == LEVEL_CRITICAL:
				return 5
			elif level == LEVEL_WARNING:
				return 4
			elif level == LEVEL_NOTICE:
				return 3
			elif level == LEVEL_INFO:
				return 2
			else:
				return 1
		except KeyError :
			return 1

	def append_to_file_io_information_output_list(self, line) :
		# Only write to the header of the "external" file
		self.__file_io_information_output_list.append(line)

	def save_result_to_file(self, output_file_path, args) :
		if not self.__file_io_result_output_list :
			self.load_to_output_list(args)

		try :
			with open(output_file_path, "w") as f :
				if self.__file_io_information_output_list :
					for line in self.__file_io_information_output_list :
						f.write(line + "\n")
				for line in self.__file_io_result_output_list :
					f.write(line + "\n")

			print("<<< Analysis report is generated: " + os.path.abspath(output_file_path) + " >>>")
			print("")

			return True
		except IOError as err:
			if DEBUG :
				print("[Error on writing output file to disk]")
			return False

	def show(self, args) :
		if not self.__file_io_result_output_list :
			self.load_to_output_list(args)

		if self.__file_io_result_output_list :
			for line in self.__file_io_result_output_list :
				print(line)

	def output(self, line) :	#Store here for later use on "print()" or "with ... open ..."
		# [Recorded here]
		self.__file_io_result_output_list.append(line)

	def output_and_force_print_console(self, line) :	#Store here for later use on "print()" or "with ... open ..."
		# [Recorded here]
		self.__file_io_result_output_list.append(line)
		print(line)

	def load_to_output_list(self, args) :
		"""
			tag => dict(level, title_msg, special_tag, cve_number)
			tag => list(detail output)
		
			print(self.__output_dict_vector_result_information)
			print(self.__output_dict_vector_result_information["vector_details"])

			Example output:
				{'WEBVIEW_RCE': {'special_tag': ['WebView', 'Remote Code Execution'], 'title': "...", 'cve_number': 'CVE-2013-4710', 'level': 'critical'}}
				"Lcom/android/mail/ui/ConversationViewFragment;->onCreateView(Landroid/view/LayoutInflater; Landroid/view/ViewGroup; 
					Landroid/os/Bundle;)Landroid/view/View; (0xa4) ---> Lcom/android/mail/browse/ConversationWebView;->addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)V"
		
			"vector_details" is a detail string of a vector separated by "\n" controlled by the users

		"""

		self.__file_io_result_output_list[:] = []	#clear the list

		wrapperTitle = TextWrapper(initial_indent=' ' * 11, subsequent_indent=' ' * 11, width=args.line_max_output_characters)
		wrapperDetail = TextWrapper(initial_indent=' ' * 15, subsequent_indent=' ' * 20, width=args.line_max_output_characters)

		sorted_output_dict_result_information = collections.OrderedDict(sorted(self.__output_dict_vector_result_information.items()))	#Sort the dictionary by key

		for tag, dict_information in sorted(sorted_output_dict_result_information.items(), key=self.__sort_by_level, reverse=True) :	#Output the sorted dictionary by level
			extra_field = ""
			if self.is_dict_information_has_special_tag(dict_information) :
				for i in dict_information["special_tag"] :
					extra_field += ("<" + i + ">")
			if self.is_dict_information_has_cve_number(dict_information) :
				extra_field += ("<#" + dict_information["cve_number"] + "#>")

			if args.show_vector_id :
				self.output("[%s] %s %s (Vector ID: %s):" % (dict_information["level"], extra_field, dict_information["summary"], tag))
			else :
				self.output("[%s] %s %s:" % (dict_information["level"], extra_field, dict_information["summary"]))

			for line in dict_information["title"].split('\n') :
				self.output(wrapperTitle.fill(line))

			if "vector_details" in dict_information :
				for line in dict_information["vector_details"].split('\n') :
					self.output(wrapperDetail.fill(line))

		self.output("------------------------------------------------------------")

		stopwatch_total_elapsed_time = self.getInf("time_total")
		stopwatch_analyze_time = self.getInf("time_analyze")
		if stopwatch_total_elapsed_time and stopwatch_analyze_time :

			if (REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE) :
				self.output_and_force_print_console("AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs")
				self.output_and_force_print_console("Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs")
			else:
				self.output("AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs")
				self.output("Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs")

		if args.store_analysis_result_in_db :

			analysis_tips_output = "("

			if args.analyze_engine_build :
				analysis_tips_output += "analyze_engine_build: " + str(args.analyze_engine_build) + ", "

			if args.analyze_tag :
				analysis_tips_output += "analyze_tag: " + str(args.analyze_tag) + ", "

			if analysis_tips_output.endswith(", ") :
				analysis_tips_output = analysis_tips_output[:-2]

			analysis_tips_output += ")"

			if (REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE) :
				self.output_and_force_print_console("<<< Analysis result has stored into database " + analysis_tips_output + " >>>")
			else :
				self.output("<<< Analysis result has stored into database " + analysis_tips_output + " >>>")


class EfficientStringSearchEngine :

	"""
		Usage:
			1.create an EfficientStringSearchEngine instance (only one should be enough)
			2.addSearchItem
			3.search
			4.get_search_result_by_match_id or get_search_result_dict_key_classname_value_methodlist_by_match_id
	"""

	def __init__(self) :
		self.__prog_list = []
		self.__dict_result_identifier_to_search_result_list = {}

	def addSearchItem(self, match_id, search_regex_or_fix_string_condition, isRegex) :
		self.__prog_list.append( (match_id, search_regex_or_fix_string_condition, isRegex) )	# "root" checking

	def search(self, vm, allstrings_list) :
		
		"""
			Example prog list input:
				[ ("match1", re.compile("PRAGMA\s*key\s*=", re.I), True), ("match2", re.compile("/system/bin/"), True), ("match3", "/system/bin/", False) ]

			Example return (Will always return the corresponding key, but the value is return only when getting the result):
				{ "match1": [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] , "match2": [] }
		"""

		## [String Search Performance Profiling]
		#string_finding_start = datetime.now()

		self.__dict_result_identifier_to_search_result_list.clear()

		for identifier, _ , _ in self.__prog_list :	#initializing the return result list
			if identifier not in self.__dict_result_identifier_to_search_result_list :
				self.__dict_result_identifier_to_search_result_list[identifier] = []

		dict_string_value_to_idx_from_file_mapping = {}

		for idx_from_file, string_value in vm.get_all_offset_from_file_and_string_value_mapping() :	#get a dictionary of string value and string idx mapping
			dict_string_value_to_idx_from_file_mapping[string_value] = idx_from_file

		## [String Search Performance Profiling]
		#string_loading_end = datetime.now()
		#print("Time for loading String: " + str(((string_loading_end - string_finding_start).total_seconds())))

		list_strings_idx_to_find = []	#string idx list
		dict_string_idx_to_identifier = {}   # Example: (52368, "match1")

		#Get the searched strings into search idxs
		for line in allstrings_list :
			for identifier, regexp, isRegex in self.__prog_list :
				if (isRegex and regexp.search(line)) or ((not isRegex) and (regexp == line)) :
					if line in dict_string_value_to_idx_from_file_mapping :   #Find idx by string
						string_idx = dict_string_value_to_idx_from_file_mapping[line]
						list_strings_idx_to_find.append(string_idx)
						dict_string_idx_to_identifier[string_idx] = identifier

		list_strings_idx_to_find = set(list_strings_idx_to_find)	#strip duplicated items

		## [String Search Performance Profiling]
		#string_finding_end = datetime.now()
		#print("Time for finding String: " + str((string_finding_end - string_finding_start).total_seconds()))

		if list_strings_idx_to_find :
			cm = vm.get_class_manager()
			for method in vm.get_methods() :
				for i in method.get_instructions():   # method.get_instructions(): Instruction
					if (i.get_op_value() == 0x1A) or (i.get_op_value() == 0x1B) :  # 0x1A = "const-string", 0x1B = "const-string/jumbo"
						ref_kind_idx = cm.get_offset_idx_by_from_file_top_idx(i.get_ref_kind())
						if ref_kind_idx in list_strings_idx_to_find :  #find string_idx in string_idx_list
							if ref_kind_idx in dict_string_idx_to_identifier :
								original_identifier_name = dict_string_idx_to_identifier[ref_kind_idx]
								self.__dict_result_identifier_to_search_result_list[original_identifier_name].append( (i.get_string(), method) )
		
		## [String Search Performance Profiling]
		#elapsed_string_finding_time = datetime.now() - string_finding_start
		#print("String Search Elapsed time: " + str(elapsed_string_finding_time.total_seconds()))
		#print("------------------------------------------------------------")

		return self.__dict_result_identifier_to_search_result_list

	def get_search_result_by_match_id(self, match_id):
		return self.__dict_result_identifier_to_search_result_list[match_id]

	def get_search_result_dict_key_classname_value_methodlist_by_match_id(self, match_id):
		"""
			Input: [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] or []
			Output: dicionary key by class name
		"""
		dict_result = {}

		search_result_value = self.__dict_result_identifier_to_search_result_list[match_id]

		try :
			if search_result_value :  #Found the corresponding url in the code
				result_list = set(search_result_value)

				for _ , result_method in result_list :  #strip duplicated item
					class_name = result_method.get_class_name()
					if class_name not in dict_result :
						dict_result[class_name] = []

					dict_result[class_name].append(result_method)
		except KeyError :
			pass

		return dict_result


class FilteringEngine :

	def __init__(self, enable_exclude_classes, str_regexp_type_excluded_classes) :
		self.__enable_exclude_classes = enable_exclude_classes
		self.__str_regexp_type_excluded_classes = str_regexp_type_excluded_classes
		self.__regexp_excluded_classes = re.compile(self.__str_regexp_type_excluded_classes, re.I)

	def get_filtering_regexp(self) :
		return self.__regexp_excluded_classes

	def filter_efficient_search_result_value(self, result) :

		if result is None :
			return []
		if (not self.__enable_exclude_classes) :
			return result

		l = []
		for found_string, method in result :
			if not self.__regexp_excluded_classes.match(method.get_class_name()) :
				l.append( (found_string, method) )

		return l

	def is_class_name_not_in_exclusion(self, class_name) :
		if self.__enable_exclude_classes :
			if self.__regexp_excluded_classes.match(class_name) :
				return False
			else :
				return True
		else :
			return True

	def is_all_of_key_class_in_dict_not_in_exclusion(self, dict_result) :
		if self.__enable_exclude_classes :
			isAllMatchExclusion = True
			for class_name, method_list in dict_result.items() :
				if not self.__regexp_excluded_classes.match(class_name) :	#any match
					isAllMatchExclusion = False
			
			if isAllMatchExclusion :
				return False

			return True
		else :
			return True

	def filter_list_of_methods(self, method_list) :
		if self.__enable_exclude_classes and method_list :
			l = []
			for method in method_list :
				if not self.__regexp_excluded_classes.match(method.get_class_name()) :
					l.append(method)
			return l
		else :
			return method_list

	def filter_list_of_classes(self, class_list) :
		if self.__enable_exclude_classes and class_list :
			l = []
			for i in class_list :
				if not self.__regexp_excluded_classes.match(i) :
					l.append(i)
			return l
		else :
			return class_list

	def filter_list_of_paths(self, vm, paths):
		if self.__enable_exclude_classes and paths :
			cm = vm.get_class_manager()

			l = []
			for path in paths :
				src_class_name, src_method_name, src_descriptor =  path.get_src(cm)
				if not self.__regexp_excluded_classes.match(src_class_name) :
					l.append(path)

			return l
		else :
			return paths

	def filter_dst_class_in_paths(self, vm, paths, excluded_class_list):
		cm = vm.get_class_manager()

		l = []
		for path in paths :
			dst_class_name, _, _ =  path.get_dst(cm)
			if dst_class_name not in excluded_class_list :
				l.append(path)

		return l

	def filter_list_of_variables(self, vm, paths) :
		"""
			Example paths input: [[('R', 8), 5050], [('R', 24), 5046]]
		"""

		if self.__enable_exclude_classes and paths :
			l = []
			for path in paths :
				access, idx = path[0]
				m_idx = path[1]
				method = vm.get_cm_method(m_idx)
				class_name = method[0]

				if not self.__regexp_excluded_classes.match(class_name) :
					l.append(path)
			return l
		else :
			return paths

	def get_class_container_dict_by_new_instance_classname_in_paths(self, vm, analysis, paths, result_idx):   #dic: key=>class_name, value=>paths
		dic_classname_to_paths = {}
		paths = self.filter_list_of_paths(vm, paths)
		for i in analysis.trace_Register_value_by_Param_in_source_Paths(vm, paths):
			if (i.getResult()[result_idx] is None) or (not i.is_class_container(result_idx)) :  #If parameter 0 is a class_container type (ex: Lclass/name;)
				continue
			class_container = i.getResult()[result_idx]
			class_name = class_container.get_class_name()
			if class_name not in dic_classname_to_paths:
				dic_classname_to_paths[class_name] = []
			dic_classname_to_paths[class_name].append(i.getPath())
		return dic_classname_to_paths


class ExpectedException(Exception) :
	def __init__(self, err_id, message):
		self.err_id = err_id
		self.message = message
	def __str__(self):
		return "[" + self.err_id + "] " + self.message

	def get_err_id(self) :
		return self.err_id

	def get_err_message(self) :
		return self.message


class StringHandler :
	def __init__(self, initial_str="") :
		self.str = initial_str

	def __repr__(self) :
		return self.str

	def __str__(self) :
		return self.str

	def append(self, new_string) :
		self.str += new_string

	def appendNewLine(self) :
		self.str += "\n"

	def get(self) :
		return self.str


def toNdkFileFormat(name):
	return "lib" + name + ".so"

def get_protectionLevel_string_by_protection_value_number(num) :
	if num == PROTECTION_NORMAL :
		return "normal"
	elif num == PROTECTION_DANGEROUS :
		return "dangerous"
	elif num == PROTECTION_SIGNATURE :
		return "signature"
	elif num == PROTECTION_SIGNATURE_OR_SYSTEM :
		return "signatureOrSystem"
	else :
		return num

def isBase64(base64_string):
		return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', base64_string)

def isSuccessBase64DecodedString(base64_string):
	# Punct: \:;/-.,?=<>+_()[]{}|"'~`*
	return re.match('^[A-Za-z0-9\\\:\;\/\-\.\,\?\=\<\>\+\_\(\)\[\]\{\}\|\"\'\~\`\*]+$', base64_string)

def isNullOrEmptyString(input_string, strip_whitespaces=False):
	if input_string is None :
		return True
	if strip_whitespaces :
		if input_string.strip() == "" :
			return True
	else :
		if input_string == "" :
			return True
	return False

def dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(list_NDK_library_classname_to_ndkso_mapping) :
	l = []
	for ndk_location , path in list_NDK_library_classname_to_ndkso_mapping:
		l.append(ndk_location)
	return l

def get_hashes_by_filename(filename):
	md5 = None
	sha1 = None
	sha256 = None
	sha512 = None
	with open(filename) as f:
		data = f.read()    
		md5 = hashlib.md5(data).hexdigest()
		sha1 = hashlib.sha1(data).hexdigest()
		sha256 = hashlib.sha256(data).hexdigest()
		sha512 = hashlib.sha512(data).hexdigest()
	return md5, sha1, sha256, sha512

def is_class_implements_interface(cls, search_interfaces, compare_type):
	class_interfaces = cls.get_interfaces()
	if class_interfaces is None:
		return False
	if compare_type == TYPE_COMPARE_ALL: # All
		for i in search_interfaces:
			if i not in class_interfaces:
				return False
		return True
	elif compare_type == TYPE_COMPARE_ANY: #Any
		for i in search_interfaces:
			if i in class_interfaces:
				return True
		return False

def get_method_ins_by_superclass_and_method(vm, super_classes, method_name, method_descriptor) :
	for cls in vm.get_classes() :
		if cls.get_superclassname() in super_classes :
			for method in cls.get_methods():
				if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor) :
					yield method

def get_method_ins_by_implement_interface_and_method(vm, implement_interface, compare_type, method_name, method_descriptor) :
	"""
		Example result:
			(Ljavax/net/ssl/HostnameVerifier; Ljava/io/Serializable;)
	"""

	for cls in vm.get_classes() :
		if is_class_implements_interface(cls, implement_interface, compare_type) :
			for method in cls.get_methods():
				if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor) :
					yield method

def get_method_ins_by_implement_interface_and_method_desc_dict(vm, implement_interface, compare_type, method_name_and_descriptor_list) :
	
	dict_result = {}

	for cls in vm.get_classes() :
		if is_class_implements_interface(cls, implement_interface, compare_type) :
			class_name = cls.get_name()
			if class_name not in dict_result :
				dict_result[class_name] = []

			for method in cls.get_methods():
				name_and_desc = method.get_name() + method.get_descriptor()
				if name_and_desc in method_name_and_descriptor_list :
					dict_result[class_name].append(method)

	return dict_result

def is_kind_string_in_ins_method(method, kind_string) :
	for ins in method.get_instructions():
		try :
			if ins.get_kind_string() == kind_string:
				return True
		except AttributeError :  # Because the instruction may not have "get_kind_string()" method
			return False
	return False

def get_all_components_by_permission(xml, permission):
    """
        Return: 
            (1) activity
            (2) activity-alias
            (3) service
            (4) receiver
            (5) provider
        who use the specific permission
    """

    find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
    dict_perms = {}

    for tag in find_tags:
        for item in xml.getElementsByTagName(tag) :
            if (item.getAttribute("android:permission") == permission) or (item.getAttribute("android:readPermission") == permission) or (item.getAttribute("android:writePermission") == permission) :
                if tag not in dict_perms :
                    dict_perms[tag] = []
                dict_perms[tag].append(item.getAttribute("android:name"))
    return dict_perms


def parseArgument():
	parser = argparse.ArgumentParser(description='AndroBugs Framework - Android App Security Vulnerability Scanner')
	parser.add_argument("-f", "--apk_file", help="APK File to analyze", type=str, required=True)
	parser.add_argument("-m", "--analyze_mode", help="Specify \"single\"(default) or \"massive\"", type=str, required=False, default=ANALYZE_MODE_SINGLE)
	parser.add_argument("-b", "--analyze_engine_build", help="Analysis build number.", type=int, required=False, default=ANALYZE_ENGINE_BUILD_DEFAULT)
	parser.add_argument("-t", "--analyze_tag", help="Analysis tag to uniquely distinguish this time of analysis.", type=str, required=False, default=None)
	parser.add_argument("-e", "--extra", help="1)Do not check(default)  2)Check  security class names, method names and native methods", type=int, required=False, default=1)
	parser.add_argument("-c", "--line_max_output_characters", help="Setup the maximum characters of analysis output in a line", type=int, required=False)
	parser.add_argument("-s", "--store_analysis_result_in_db", help="Specify this argument if you want to store the analysis result in MongoDB. Please add this argument if you have MongoDB connection.", action="store_true")
	parser.add_argument("-v", "--show_vector_id", help="Specify this argument if you want to see the Vector ID for each vector.", action="store_true")

	#When you want to use "report_output_dir", remember to use "os.path.join(args.report_output_dir, [filename])"
	parser.add_argument("-o", "--report_output_dir", help="Analysis Report Output Directory", type=str, required=False, default=DIRECTORY_REPORT_OUTPUT)
	
	args = parser.parse_args()
	return args

def __analyze(writer, args) :

	"""
		Exception:
			apk_file_not_exist
			classes_dex_not_in_apk
	"""

	#StopWatch: Counting execution time...
	stopwatch_start = datetime.now()

	efficientStringSearchEngine = EfficientStringSearchEngine()
	filteringEngine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)

	isUsingSQLCipher = False
	isMasterKeyVulnerability = False

	if args.line_max_output_characters is None :
		if platform.system().lower() == "windows" :
			args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_WINDOWS - LINE_MAX_OUTPUT_INDENT
		else :
			args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_LINUX - LINE_MAX_OUTPUT_INDENT

	if not os.path.isdir(args.report_output_dir) :
		os.mkdir(args.report_output_dir)

	writer.writeInf_ForceNoPrint("analyze_mode", args.analyze_mode)
	writer.writeInf_ForceNoPrint("analyze_engine_build", args.analyze_engine_build)
	if args.analyze_tag :
		writer.writeInf_ForceNoPrint("analyze_tag", args.analyze_tag)

	APK_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file
	apk_Path = APK_FILE_NAME_STRING  # + ".apk"

	if (".." in args.apk_file) :
		raise ExpectedException("apk_file_name_slash_twodots_error", "APK 파일 이름에는 슬래시(/) 또는 두 개의 점(...)을 사용할 수 없습니다. (File: " + apk_Path + ").") 

	if not os.path.isfile(apk_Path) :
		raise ExpectedException("apk_file_not_exist", "APK이 존재하지 않습니다. (File: " + apk_Path + ").")

	if args.store_analysis_result_in_db :
		try:
			imp.find_module('pymongo')
			found_pymongo_lib = True
		except ImportError:
			found_pymongo_lib = False

		if not found_pymongo_lib :
			pass

			# Cause some unexpected behavior on Linux => Temporarily comment it out
			# raise ExpectedException("libs_not_found_pymongo", "Python library \"pymongo\" is not found. Please install the library first: http://api.mongodb.org/python/current/installation.html.")

	#apk_filepath_relative = apk_Path
	apk_filepath_absolute = os.path.abspath(apk_Path)

	#writer.writeInf_ForceNoPrint("apk_filepath_relative", apk_filepath_relative)
	writer.writeInf_ForceNoPrint("apk_filepath_absolute", apk_filepath_absolute)

	apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (1024 * 1024)
	writer.writeInf_ForceNoPrint("apk_file_size", apk_file_size)

	writer.update_analyze_status("loading_apk")

	writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.utcnow())

	a = apk.APK(apk_Path) 

	writer.update_analyze_status("starting_apk")

	package_name = a.get_package()

	if isNullOrEmptyString(package_name, True) :
		raise ExpectedException("package_name_empty", "Package이름이 존재하지 않습니다. (File: " + apk_Path + ").")

	writer.writeInf("platform", "Android", "Platform")
	writer.writeInf("package_name", str(package_name), "Package Name")

	# Check: http://developer.android.com/guide/topics/manifest/manifest-element.html
	if not isNullOrEmptyString(a.get_androidversion_name()):
		try :
			writer.writeInf("package_version_name", str(a.get_androidversion_name()), "Package Version Name")
		except :
			writer.writeInf("package_version_name", a.get_androidversion_name().encode('ascii', 'ignore'), "Package Version Name")

	if not isNullOrEmptyString(a.get_androidversion_code()):
		# The version number shown to users. This attribute can be set as a raw string or as a reference to a string resource. 
		# The string has no other purpose than to be displayed to users. 
		try :
			writer.writeInf("package_version_code", int(a.get_androidversion_code()), "Package Version Code")
		except ValueError :
			writer.writeInf("package_version_code", a.get_androidversion_code(), "Package Version Code")

	if len(a.get_dex()) == 0:
		raise ExpectedException("classes_dex_not_in_apk", "APK 파일이 손상되었습니다. \"filename.pilename\" 파일을 찾을 수 없습니다. (File: " + apk_Path + ").")

	try:
		str_min_sdk_version = a.get_min_sdk_version()
		if (str_min_sdk_version is None) or (str_min_sdk_version == "") :
			raise ValueError
		else:
			int_min_sdk = int(str_min_sdk_version)
			writer.writeInf("minSdk", int_min_sdk, "Min Sdk")
	except ValueError:
		# Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
		# If "minSdk" is not set, the default value is "1"
		writer.writeInf("minSdk", 1, "Min Sdk")
		int_min_sdk = 1

	try:
		str_target_sdk_version = a.get_target_sdk_version()
		if (str_target_sdk_version is None) or (str_target_sdk_version == "") :
			raise ValueError
		else:
			int_target_sdk = int(str_target_sdk_version)
			writer.writeInf("targetSdk", int_target_sdk, "Target Sdk")
	except ValueError:
		# Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
		# If not set, the default value equals that given to minSdkVersion.
		int_target_sdk = int_min_sdk

	md5, sha1, sha256, sha512 = get_hashes_by_filename(APK_FILE_NAME_STRING)
	writer.writeInf("file_md5", md5, "MD5   ")
	writer.writeInf("file_sha1", sha1, "SHA1  ")
	writer.writeInf("file_sha256", sha256, "SHA256")
	writer.writeInf("file_sha512", sha512, "SHA512")

	writer.update_analyze_status("starting_dvm")

	d = dvm.DalvikVMFormat(a.get_dex())

	writer.update_analyze_status("starting_analyze")

	vmx = analysis.VMAnalysis(d)

	writer.update_analyze_status("starting_androbugs")

	analyze_start = datetime.now()

	# ////////////////////////////////////////////////////////////////////////////////////////////////////////////

	all_permissions = a.get_permissions()

	allstrings = d.get_strings()
	allurls_strip_duplicated = []

	# ------------------------------------------------------------------------
	#[Important: String Efficient Searching Engine]
	# >>>>STRING_SEARCH<<<<
	#addSearchItem params: (1)match_id  (2)regex or string(url or string you want to find), (3)is using regex for parameter 2
	efficientStringSearchEngine.addSearchItem("$__possibly_check_root__", re.compile("/system/bin"), True)	# "root" checking
	efficientStringSearchEngine.addSearchItem("$__possibly_check_su__", "su", False)	# "root" checking2
	efficientStringSearchEngine.addSearchItem("$__sqlite_encryption__", re.compile("PRAGMA\s*key\s*=", re.I), True)	#SQLite encryption checking
	
	print("------------------------------------------------------------")

	#Print all urls without SSL:

	exception_url_string = ["http://example.com",
							"http://example.com/",
							"http://www.example.com",
							"http://www.example.com/",
							"http://www.google-analytics.com/collect",
							"http://www.google-analytics.com",
							"http://hostname/?",
							"http://hostname/"]

	for line in allstrings:
		if re.match('http\:\/\/(.+)', line):    #^https?\:\/\/(.+)$
			allurls_strip_duplicated.append(line)

	allurls_strip_non_duplicated = sorted(set(allurls_strip_duplicated))
	allurls_strip_non_duplicated_final = []

	if allurls_strip_non_duplicated:
		for url in allurls_strip_non_duplicated :
			if (url not in exception_url_string) and (not url.startswith("http://schemas.android.com/")) and \
													 (not url.startswith("http://www.w3.org/")) and \
													 (not url.startswith("http://apache.org/")) and \
													 (not url.startswith("http://xml.org/")) and \
													 (not url.startswith("http://localhost/")) and \
													 (not url.startswith("http://java.sun.com/")) and \
													 (not url.endswith("/namespace")) and \
													 (not url.endswith("-dtd")) and \
													 (not url.endswith(".dtd")) and \
													 (not url.endswith("-handler")) and \
													 (not url.endswith("-instance")) :
				# >>>>STRING_SEARCH<<<<
				efficientStringSearchEngine.addSearchItem(url, url, False)	#use url as "key"

				allurls_strip_non_duplicated_final.append(url)

	# ------------------------------------------------------------------------

	#Base64 String decoding:
	list_base64_success_decoded_string_to_original_mapping = {}
	list_base64_excluded_original_string = ["endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=", "Liouciou"] #exclusion list

	for line in allstrings :
		if (isBase64(line)) and (len(line) >= 3) :
			try:
				decoded_string = base64.b64decode(line)
				if isSuccessBase64DecodedString(decoded_string) :
					if len(decoded_string) > 3:
						if (decoded_string not in list_base64_success_decoded_string_to_original_mapping) and (line not in list_base64_excluded_original_string):
							list_base64_success_decoded_string_to_original_mapping[decoded_string] = line
							# >>>>STRING_SEARCH<<<<
							efficientStringSearchEngine.addSearchItem(line, line, False)
			except:
				pass

	# ------------------------------------------------------------------------

	# >>>>STRING_SEARCH<<<<

	#start the search core engine
	efficientStringSearchEngine.search(d, allstrings)

	# ------------------------------------------------------------------------

	#pre-run to avoid all the urls are in exclusion list but the results are shown
	allurls_strip_non_duplicated_final_prerun_count = 0
	for url in allurls_strip_non_duplicated_final :
		dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(url)
		if filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping) :
			allurls_strip_non_duplicated_final_prerun_count = allurls_strip_non_duplicated_final_prerun_count + 1


	if allurls_strip_non_duplicated_final_prerun_count != 0:
		writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_CRITICAL, "SSL Connection 검사", "SSL을 사용하지 않는 URLs입니다. (Total:" + str(allurls_strip_non_duplicated_final_prerun_count) + "):", ["SSL_Security"])
		
		for url in allurls_strip_non_duplicated_final :

			dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(url)
			if not filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping) :
				continue

			writer.write(url)

			try :
				if dict_class_to_method_mapping :  #Found the corresponding url in the code
					for _ , result_method_list in dict_class_to_method_mapping.items() :
						for result_method in result_method_list :  #strip duplicated item
							if filteringEngine.is_class_name_not_in_exclusion(result_method.get_class_name()) :
								source_classes_and_functions = (result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
								writer.write("    => " + source_classes_and_functions)
					
			except KeyError:
				pass

	else:
		writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_INFO, "SSL Connection 검사", "SSL을 사용하지 않는 URLs을 발견하지 못헀습니다. (알림: 만약 URL 문자열을 암호화했다면, 그것을 발견할 수 없습니다.).", ["SSL_Security"])
		
	#--------------------------------------------------------------------
	
	regexGerneralRestricted = ".*(config|setting|constant).*";
	regexSecurityRestricted = ".*(encrypt|decrypt|encod|decod|aes|sha1|sha256|sha512|md5).*"   #No need to add "sha1" and "des"
	#show the user which package is excluded

	prog = re.compile(regexGerneralRestricted, re.I)
	prog_sec = re.compile(regexSecurityRestricted, re.I)

	# Security methods finding:

	if args.extra == 2 : #The output may be too verbose, so make it an option

		list_security_related_methods = []

		for method in d.get_methods():
			if prog.match(method.get_name()) or prog_sec.match(method.get_name()):
				if filteringEngine.is_class_name_not_in_exclusion(method.get_class_name()):
					# Need to exclude "onConfigurationChanged (Landroid/content/res/Configuration;)V"
					if (method.get_name() != 'onConfigurationChanged') and (method.get_descriptor() != '(Landroid/content/res/Configuration;)V') :
						list_security_related_methods.append(method)

		if list_security_related_methods :
			writer.startWriter("Security_Methods", LEVEL_NOTICE, "Security Methods 검사", "보안 관련 메서드 이름 발견:")
			for method in list_security_related_methods :
				writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())
		else :
			writer.startWriter("Security_Methods", LEVEL_INFO, "Security Methods 검사", "보안 관련 문자열을 포함하는 메서드 이름을 검색하지 못했습니다.")
			

	#------------------------------------------------------------------------------------------------------

	# Security classes finding:

	if args.extra == 2 : #The output may be too verbose, so make it an option
		list_security_related_classes = []

		for current_class in d.get_classes():
			if prog.match(current_class.get_name()) or prog_sec.match(current_class.get_name()):
				if filteringEngine.is_class_name_not_in_exclusion(current_class.get_name()):
					list_security_related_classes.append(current_class)

		if list_security_related_classes :
			writer.startWriter("Security_Classes", LEVEL_NOTICE, "Security Classes 검사", "보안 관련 클래스 이름 발견:")
			
			for current_class in list_security_related_classes :
				writer.write(current_class.get_name())
		else :
			writer.startWriter("Security_Classes", LEVEL_INFO, "Security Classes 검사", "보안 관련 문자열을 포함하는 클래스 이름을 검색하지 못했습니다.")
			
	#------------------------------------------------------------------------------------------------------

	#Master Key Vulnerability checking:

	dexes_count = 0
	all_files = a.get_files()
	for f in all_files:
		if f == 'classes.dex':
			dexes_count += 1

	if dexes_count > 1:
		isMasterKeyVulnerability = True
		
	if isMasterKeyVulnerability :
		writer.startWriter("MASTER_KEY", LEVEL_CRITICAL, "마스터 키 유형 I 취약성", "이 APK에는 마스터 키 유형 I 취약성이 있습니다.", None, "CVE-2013-4787")
	else :
		writer.startWriter("MASTER_KEY", LEVEL_INFO, "마스터 키 유형 I 취약성", "이 APK에는 마스터 키 유형 I 취약성이 없습니다.", None, "CVE-2013-4787")

	#------------------------------------------------------------------------------------------------------
	# Certificate checking (Prerequisite: 1.directory name "tmp" available  2.keytool command is available)

	# Comment out this code because chilkat may not be supported easily by every Linux
	# You can uncomment it if you have successfully installed the chilkat

	"""
	import chilkat

	rsa_signature_filename = a.get_signature_name()    #a.get_signature_name() return a signature file name

	if rsa_signature_filename is None:
		writer.startWriter("CERT_SIGNED", LEVEL_CRITICAL, "Android App Signature", "This app is not signed. It can not be installed or upgraded on Android system.", ["Signature"])
	else:
		try:
			success, cert = a.get_certificate(rsa_signature_filename)
			if success:
				if (cert.subjectCN() == 'Android Debug') or (cert.issuerCN() == 'Android Debug') :
					writer.startWriter("CERT_SIGNED", LEVEL_CRITICAL, "Android App Signature", "This app is signed by 'Android Debug' certificate which is only for testing. DO NOT release this app in production!", ["Signature"])
				else:
					writer.startWriter("CERT_SIGNED", LEVEL_INFO, "Android App Signature", "This app is signed by your own certificate (SubjectCN: %s, IssuerCN: %s)." % (cert.subjectCN(), cert.issuerCN()), ["Signature"])
			else:
				writer.startWriter("CERT_SIGNED", LEVEL_INFO, "Android App Signature", "We cannot tell whether the app is signed or not because we are unable to load the certificate of app.", ["Signature"])

		except IOError:
			pass
	"""

	#------------------------------------------------------------------------------------------------------

	# DEBUGGABLE checking:

	is_debug_open = a.is_debuggable()   #Check 'android:debuggable'
	if is_debug_open:
		writer.startWriter("DEBUGGABLE", LEVEL_CRITICAL, "Android Debug Mode 검사", 
			"AndroidManifest.xml에서 DEBUG 모드가 ON(android:debugable=\"true\")입니다. 이것은 매우 위험합니다. 공격자는 로그캣을 통해 디버그 메시지를 탐지할 수 있습니다. 릴리스된 응용 프로그램인 경우 DEBUG 모드를 비활성화하십시오.", ["Debug"])

	else:
		writer.startWriter("DEBUGGABLE", LEVEL_INFO, "Android Debug Mode 검사", "AndroidManifest.xml에서 DEBUG 모드가 OFF(android:debugable=\"false\")입니다.", ["Debug"])

	#------------------------------------------------------------------------------------------------------

	# Checking whether the app is checking debuggable:

	"""
		Java code checking debuggable:
			boolean isDebuggable = (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE));
			if (isDebuggable) { }

		Smali code checking debuggable:
			invoke-virtual {p0}, Lcom/example/androiddebuggable/MainActivity;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;
			move-result-object v1
			iget v1, v1, Landroid/content/pm/ApplicationInfo;->flags:I
			and-int/lit8 v1, v1, 0x2
			if-eqz v1, :cond_0

		Checking Pattern:
			1. Find tainted calling field: Landroid/content/pm/ApplicationInfo;->flags:I
			2. Get the next instruction of the calling field: Landroid/content/pm/ApplicationInfo;->flags:I
			3. Check whether the next instruction is 0xDD(and-int/lit8) and make sure the register numbers are all matched
				iget [[v1]], v1, [[[Landroid/content/pm/ApplicationInfo;->flags:I]]]
				and-int/lit8 v1, [[v1]], [0x2]

	"""
	list_detected_FLAG_DEBUGGABLE_path = []
	field_ApplicationInfo_flags_debuggable = vmx.get_tainted_field("Landroid/content/pm/ApplicationInfo;" ,"flags", "I")

	if field_ApplicationInfo_flags_debuggable :
		for path, stack in field_ApplicationInfo_flags_debuggable.get_paths_and_stacks(d, filteringEngine.get_filtering_regexp()):
			last_one_ins = stack.gets()[-1]
			last_two_ins = stack.gets()[-2]

			if (last_one_ins is not None) and (last_two_ins is not None) :
				try:
					if (last_one_ins[0] == 0xDD) and (last_two_ins[1][0][1] == last_one_ins[1][1][1]) and (last_one_ins[1][2][1] == 2) :  #and-int/lit8 vx,vy,lit8
						list_detected_FLAG_DEBUGGABLE_path.append(path)
					"""
						Example 1:
							last_two_ins => [82, [(0, 1), (0, 1), (258, 16, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
							last_one_ins => [221, [(0, 1), (0, 1), (1, 2)]]

						Example 2:
							last_two_ins => [82, [(0, 2), (0, 0), (258, 896, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
							last_one_ins => [221, [(0, 2), (0, 2), (1, 2)]]

						Java code:
							stack.show()
							print(last_one_ins)
							print(last_two_ins)
					"""
				except:
					pass

	if list_detected_FLAG_DEBUGGABLE_path :
		writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE, "Checking Android Debug Mode 검사를 위한 코드", "AndroidManifest.xml에서 \"ApplicationInfo.FLAG_DEBUGGABLE\" 검사하는 코드를 발견:", ["Debug", "Hacker"])

		for path in list_detected_FLAG_DEBUGGABLE_path:
			writer.show_single_PathVariable(d, path)
	else:
		writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Checking Android Debug Mode 검사를 위한 코드", "AndroidManifest.xml에서 \"ApplicationInfo.FLAG_DEBUGGABLE\" 검사하는 코드를 발견하지 못했습니다.", ["Debug", "Hacker"])

	#----------------------------------------------------------------------------------

	ACCESS_MOCK_LOCATION = "android.permission.ACCESS_MOCK_LOCATION"
	if ACCESS_MOCK_LOCATION in all_permissions:
		writer.startWriter("USE_PERMISSION_ACCESS_MOCK_LOCATION", LEVEL_CRITICAL, "불필요한 권한 검사", "권한 'android.permission.ACCESS_MOCK_LOCATION'은 에뮬레이터 환경에서만 작동합니다. 릴리스된 응용 프로그램인 경우 이 권한을 제거하십시오.")
	else:
		writer.startWriter("USE_PERMISSION_ACCESS_MOCK_LOCATION", LEVEL_INFO, "불필요한 권한 검사", "권한 'android.permission.ACCESS_MOCK_LOCATION' 올바르게 설정되어 있습니다.")

	#----------------------------------------------------------------------------------

	permissionNameOfWrongPermissionGroup = a.get_permission_tag_wrong_settings_names()

	if permissionNameOfWrongPermissionGroup:  #If the list is not empty
		writer.startWriter("PERMISSION_GROUP_EMPTY_VALUE", LEVEL_CRITICAL, "AndroidManifest 권한그룹 검사", 
			"'permissionGroup' 속성을 빈 값으로 설정하면 권한 정의가 잘못되어 다른 앱에서 권한을 사용할 수 없게 됩니다.")

		for name in permissionNameOfWrongPermissionGroup:
			writer.write("권한 이름 `permissionGroup` 속성에 있는 '%s'이 빈 값으로 설정되어 있습니다." % (name))
	else:
		writer.startWriter("PERMISSION_GROUP_EMPTY_VALUE", LEVEL_INFO, "AndroidManifest 권한그룹 검사", "PermissionGroup in permission tag of AndroidManifest sets correctly.")

	#----------------------------------------------------------------------------------

	#Critical use-permission check:
	user_permission_critical_manufacturer = ["android.permission.INSTALL_PACKAGES", "android.permission.WRITE_SECURE_SETTINGS"]
	user_permission_critical = ["android.permission.MOUNT_FORMAT_FILESYSTEMS", "android.permission.MOUNT_UNMOUNT_FILESYSTEMS", "android.permission.RESTART_PACKAGES"]

	list_user_permission_critical_manufacturer = []
	list_user_permission_critical = []

	for permission in all_permissions:
		if permission in user_permission_critical_manufacturer:
			list_user_permission_critical_manufacturer.append(permission)
		if permission in user_permission_critical:
			list_user_permission_critical.append(permission)
	
	if list_user_permission_critical_manufacturer or list_user_permission_critical:
		if list_user_permission_critical_manufacturer:
			writer.startWriter("USE_PERMISSION_SYSTEM_APP", LEVEL_CRITICAL, "AndroidManifest System 사용 권한 검사", "이 앱은 개발업체 또는 Google에서 릴리스하고 서명하며 '/system/app' 아래에 있어야 합니다. 그렇지 않으면 악성 앱일 수 있습니다.")

			for permission in list_user_permission_critical_manufacturer:
				writer.write("System use-permission found: \"" + permission + "\"")

		if list_user_permission_critical:
			writer.startWriter("USE_PERMISSION_CRITICAL", LEVEL_CRITICAL, "AndroidManifest System 사용 권한 검사", "이 앱은 매우 높은 권한을 가지고 있습니다.")

			for permission in list_user_permission_critical:
				writer.write("Critical use-permission found: \"" + permission + "\"")
	else :
		writer.startWriter("USE_PERMISSION_SYSTEM_APP", LEVEL_INFO, "AndroidManifest System 사용 권한 검사", "시스템의 중요한 사용 권한을 찾을 수 없습니다.")

	#----------------------------------------------------------------------------------

	isSuggestGCM = False
	if int_min_sdk is not None:
		if int_min_sdk < 8: #Android 2.2=SDK 8
			isSuggestGCM = True

	if isSuggestGCM :

		output_string = """minSdk의 버전: """ + str(int_min_sdk) + """
You are now allowing minSdk버전을 8보다 낮은 버전을 사용하고 있습니다. Google 클라우드 메시징(푸시 메시지) 서비스는 Android SDK > = 8(Android 2.2)만 허용합니다. 참조: http://developer.android.com/about/dashboards/index.html."""
		writer.startWriter("MANIFEST_GCM", LEVEL_NOTICE, "Google 클라우드 메세지 제안", output_string)

	else :

		writer.startWriter("MANIFEST_GCM", LEVEL_INFO, "Google 클라우드 메세지 제안", "제안사항이 없습니다.")

	#------------------------------------------------------------------------------------------------------
	#Find network methods:

	# pkg_xxx is a 'PathP' object
	pkg_URLConnection = vmx.get_tainted_packages().search_packages("Ljava/net/URLConnection;")    
	pkg_HttpURLConnection = vmx.get_tainted_packages().search_packages("Ljava/net/HttpURLConnection;")
	pkg_HttpsURLConnection = vmx.get_tainted_packages().search_packages("Ljavax/net/ssl/HttpsURLConnection;")
	pkg_DefaultHttpClient = vmx.get_tainted_packages().search_packages("Lorg/apache/http/impl/client/DefaultHttpClient;")
	pkg_HttpClient = vmx.get_tainted_packages().search_packages("Lorg/apache/http/client/HttpClient;")

	pkg_URLConnection = filteringEngine.filter_list_of_paths(d, pkg_URLConnection)
	pkg_HttpURLConnection = filteringEngine.filter_list_of_paths(d, pkg_HttpURLConnection)
	pkg_HttpsURLConnection = filteringEngine.filter_list_of_paths(d, pkg_HttpsURLConnection)
	pkg_DefaultHttpClient = filteringEngine.filter_list_of_paths(d, pkg_DefaultHttpClient)
	pkg_HttpClient = filteringEngine.filter_list_of_paths(d, pkg_HttpClient)

	# size_pkg_URLConnection = len(pkg_URLConnection)
	# size_pkg_HttpURLConnection = len(pkg_HttpURLConnection)
	# size_pkg_HttpsURLConnection = len(pkg_HttpsURLConnection)
	# size_pkg_DefaultHttpClient = len(pkg_DefaultHttpClient)
	# size_pkg_HttpClient = len(pkg_HttpClient)

	# Provide 2 options for users:
	# 1.Show the network-related class or not
	# 2.Exclude 'Lcom/google/' package or 'Lcom/facebook/' package  or not
	# **Should Make the output path sorted by class name

	if pkg_URLConnection or pkg_HttpURLConnection or pkg_HttpsURLConnection or pkg_DefaultHttpClient or pkg_HttpClient:

		if "android.permission.INTERNET" in all_permissions:
			writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_INFO, "인터넷 접근 검사", 
						"이 앱은 HTTP 프로토콜을 통해 인터넷을 사용하고 있습니다.")

		else:
			writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_CRITICAL, "인터넷 접근 검사", 
						"이 앱에는 일부 인터넷 액세스 코드가 있지만 AndroidManifest안에 있는 'android.permission.INTERNET'이 설정되어 있지 않습니다.")

		# if pkg_URLConnection:
		# 	print("        =>URLConnection:")
		# 	analysis.show_Paths(d, pkg_URLConnection)
		# 	print
		# if pkg_HttpURLConnection:
		# 	print("        =>HttpURLConnection:")
		# 	analysis.show_Paths(d, pkg_HttpURLConnection)
		# 	print
		# if pkg_HttpsURLConnection:
		# 	print("        =>HttpsURLConnection:")
		# 	analysis.show_Paths(d, pkg_HttpsURLConnection)
		# 	print
		# if pkg_DefaultHttpClient:
		# 	print("        =>DefaultHttpClient:")
		# 	analysis.show_Paths(d, pkg_DefaultHttpClient)
		# 	print
		# if pkg_HttpClient:
		# 	print("        =>HttpClient:")
		# 	analysis.show_Paths(d, pkg_HttpClient)
		# 	print

	else:
		writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_INFO, "인터넷 접근 검사", "HTTP 관련 연결 코드를 찾을 수 없습니다.")

	# ------------------------------------------------------------------------

	#Base64 String decoding:

	organized_list_base64_success_decoded_string_to_original_mapping = []
	for decoded_string, original_string in list_base64_success_decoded_string_to_original_mapping.items():
		dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(original_string)
		if filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping) :	
			"""
				All of same string found are inside the excluded packages.
				Only the strings found the original class will be added.
			"""
			organized_list_base64_success_decoded_string_to_original_mapping.append( (decoded_string, original_string, dict_class_to_method_mapping) )


	if organized_list_base64_success_decoded_string_to_original_mapping:  #The result is from the upper code section

		list_base64_decoded_urls = {}

		writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_CRITICAL, "Base64 문자열 인코딩", "Found Base64 인코딩 발견 \"String(s)\" (총: " + str(len(organized_list_base64_success_decoded_string_to_original_mapping)) + "). We cannot guarantee all of the Strings are Base64 encoding and also we will not show you the decoded binary file:", ["Hacker"])

		for decoded_string, original_string, dict_class_to_method_mapping in organized_list_base64_success_decoded_string_to_original_mapping : 

			writer.write(decoded_string)
			writer.write("    ->원본 인코딩 문자열: " + original_string)
			
			if dict_class_to_method_mapping :
				for class_name, result_method_list in dict_class_to_method_mapping.items() :
					for result_method in result_method_list :
						source_classes_and_functions = (result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
						writer.write("    ->From class: " + source_classes_and_functions)

			if "http://" in  decoded_string:
				list_base64_decoded_urls[decoded_string] = original_string

		if list_base64_decoded_urls :

			writer.startWriter("HACKER_BASE64_URL_DECODE", LEVEL_CRITICAL, "Base64 문자열 인코딩", "모든 문자열로 부터 Base64 인코딩 \"HTTP URLs without SSL\" (총: " + str(len(list_base64_decoded_urls)) + ")", ["SSL_Security", "Hacker"])

			for decoded_string, original_string in list_base64_decoded_urls.items():

				dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(original_string)

				if not filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping) :	#All of the same string found are inside the excluded packages
					continue

				writer.write(decoded_string)
				writer.write("    ->원본 인코딩 문자열: " + original_string)

				if dict_class_to_method_mapping :
					for class_name, result_method_list in dict_class_to_method_mapping.items() :
						for result_method in result_method_list :
							source_classes_and_functions = (result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
							writer.write("    ->From class: " + source_classes_and_functions)

	else:
		writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_INFO, "Base64 문자열 인코딩", "인코딩된 Base64 문자열 또는 URL을 찾을 수 없습니다.", ["Hacker"])

	# ------------------------------------------------------------------------
	#WebView addJavascriptInterface checking:

	#Don't match class name because it might use the subclass of WebView
	path_WebView_addJavascriptInterface = vmx.get_tainted_packages().search_methods_exact_match("addJavascriptInterface", "(Ljava/lang/Object; Ljava/lang/String;)V")
	path_WebView_addJavascriptInterface = filteringEngine.filter_list_of_paths(d, path_WebView_addJavascriptInterface)

	if path_WebView_addJavascriptInterface:

		output_string = """중요한 WebView "addJavascriptInterface"취약성을 찾았습니다. 이 메서드를 사용하여 JavaScript가 호스트 응용 프로그램을 제어할 수 있습니다. 
이것은 강력한 기능이지만 자바스크립트가 삽입된 객체의 공개 필드에 접근하기 위해 반사를 사용할 수 있기 때문에 API 수준 JELLY_BEAN(4.2) 이하를 대상으로 하는 애플리케이션의 보안 위험도 있다. 신뢰할 수 없는 콘텐츠를 포함하는 WebView에서 이 메서드를 사용하면 공격자가 의도하지 않은 방법으로 호스트 응용 프로그램을 조작하여 호스트 응용 프로그램의 권한으로 Java 코드를 실행할 수 있습니다.
참조: 
  1."http://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String) "
  2.https://labs.mwrinfosecurity.com/blog/2013/09/24/webview-addjavascriptinterface-remote-code-execution/
  3.http://50.56.33.56/blog/?p=314
  4.http://blog.trustlook.com/2013/09/04/alert-android-webview-addjavascriptinterface-code-execution-vulnerability/
아래 코드를 수정해 주십시오.:"""

		writer.startWriter("WEBVIEW_RCE", LEVEL_CRITICAL, "WebView RCE 취약점 검사", output_string, ["WebView", "Remote Code Execution"], "CVE-2013-4710")
		writer.show_Paths(d, path_WebView_addJavascriptInterface)

	else:

		writer.startWriter("WEBVIEW_RCE", LEVEL_INFO, "WebView RCE 취약점 검사", "WebView addJavascriptInterface 취약점을 찾을 수 없습니다.", ["WebView", "Remote Code Execution"], "CVE-2013-4710")

	# ------------------------------------------------------------------------
	#KeyStore null PWD checking:

	list_no_pwd_probably_ssl_pinning_keystore = []
	list_no_pwd_keystore = []
	list_protected_keystore = []

	path_KeyStore = vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/security/KeyStore;", "load", "(Ljava/io/InputStream; [C)V")
	path_KeyStore = filteringEngine.filter_list_of_paths(d, path_KeyStore)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_KeyStore):
		if i.getResult()[2] == 0:  #null = 0 = Not using password
			if (i.is_class_container(1)) :
				clz_invoked = i.getResult()[1]
				if clz_invoked.get_class_name() == "Ljava/io/ByteArrayInputStream;" :
					list_no_pwd_probably_ssl_pinning_keystore.append(i.getPath())
				else :
					list_no_pwd_keystore.append(i.getPath())
			else :
				if i.getResult()[1] == 0:  #null = 0 
					list_no_pwd_probably_ssl_pinning_keystore.append(i.getPath())
				else :
					list_no_pwd_keystore.append(i.getPath())
		else:
			list_protected_keystore.append(i.getPath())

	if (not list_no_pwd_keystore) and (not list_protected_keystore) and (not list_no_pwd_probably_ssl_pinning_keystore):

		writer.startWriter("HACKER_KEYSTORE_NO_PWD", LEVEL_INFO, "KeyStore 보호 검사", 
			"키스토어를 사용하지 않기 때문에 암호로 보호되는 키스토어 확인을 무시하십시오.", ["KeyStore", "Hacker"])

	else:
		if list_no_pwd_probably_ssl_pinning_keystore:

			writer.startWriter("HACKER_KEYSTORE_SSL_PINNING", LEVEL_CRITICAL, "KeyStore 보호 검사", 
				"아래의 키 저장소는 SSL 고정 작업을 위해 \"byte array\" 또는 \"hard-coded cert info\"를 사용하는 것 같습니다. (총: " + str(len(list_no_pwd_probably_ssl_pinning_keystore)) + "). 수동으로 확인하십시오:", ["KeyStore", "Hacker"])

			for keystore in list_no_pwd_probably_ssl_pinning_keystore:
				writer.show_Path(d, keystore)

		if list_no_pwd_keystore:

			writer.startWriter("HACKER_KEYSTORE_NO_PWD", LEVEL_CRITICAL, "KeyStore 보호 검사", 
				"아래 키 저장소는 암호로 보호되는 \"NOT\"인 것 같습니다. (총: " + str(len(list_no_pwd_keystore)) + "). 수동으로 확인하십시오:", ["KeyStore", "Hacker"])

			for keystore in list_no_pwd_keystore:
				writer.show_Path(d, keystore)

		if list_protected_keystore:
			
			writer.startWriter("HACKER_KEYSTORE_SSL_PINNING2", LEVEL_NOTICE, "KeyStore 보호 검사", 
				"아래의 키 저장소는 암호로 \"protected\"되어 있으며 SSL-pinning을 사용하는 것 같습니다. (총: " + str(len(list_protected_keystore)) + "). \"Portecle\" 도구를 사용하여 KeyStore의 인증서를 관리할 수 있습니다:", ["KeyStore", "Hacker"])

			for keystore in list_protected_keystore:
				writer.show_Path(d, keystore)

	# ------------------------------------------------------------------------
	#Find all keystore

	list_keystore_file_name = []
	list_possible_keystore_file_name = []

	for name, _, _ in a.get_files_information() :
		"""
			1.Name includes cert (search under /res/raw)
			2.ends with .bks (search all)
		"""
		if name.endswith(".bks") or name.endswith(".jks") :
			if (name.startswith("res/")) and (not name.startswith("res/raw/")) :   #If any files found on "/res" dir, only get from "/res/raw"
				continue
			list_keystore_file_name.append(name)
		elif ("keystore" in name) or ("cert" in name) :
			if (name.startswith("res/")) and (not name.startswith("res/raw/")) :   #If any files found on "/res" dir, only get from "/res/raw
				continue
			list_possible_keystore_file_name.append(name)

	if list_keystore_file_name or list_possible_keystore_file_name :
		if list_keystore_file_name :
			writer.startWriter("HACKER_KEYSTORE_LOCATION1", LEVEL_NOTICE, "KeyStore 파일 위치", "BKS Keystore 파일:", ["KeyStore", "Hacker"])
			for i in list_keystore_file_name:
				writer.write(i)

		if list_possible_keystore_file_name:
			writer.startWriter("HACKER_KEYSTORE_LOCATION2", LEVEL_NOTICE, "가능성있는 KeyStore 파일 위치", "가능성있는 BKS keystore 파일:", ["KeyStore", "Hacker"])
			for i in list_possible_keystore_file_name:
				writer.write(i)
	else :
		writer.startWriter("HACKER_KEYSTORE_LOCATION1", LEVEL_INFO, "KeyStore 파일 위치", 
			"가능성있는 BKS 키 저장소 또는 인증서 키 저장소 파일을 찾지 못했습니다(알림: 이 앱이 keystore를 사용하지 않는 것은 아닙니다.):", ["KeyStore", "Hacker"])

	# ------------------------------------------------------------------------
	#BKS KeyStore checking:

	"""
		Example:
	    const-string v11, "BKS"
	    invoke-static {v11}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;
	"""

	list_Non_BKS_keystore = []
	path_BKS_KeyStore = vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/security/KeyStore;", "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;")
	path_BKS_KeyStore = filteringEngine.filter_list_of_paths(d, path_BKS_KeyStore)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_BKS_KeyStore):
		if i.getResult()[0] is None:
			continue
		if (i.is_string(i.getResult()[0])) and ((i.getResult()[0]).upper() != "BKS") :
			list_Non_BKS_keystore.append(i.getPath())

	if list_Non_BKS_keystore:
		writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_CRITICAL, "KeyStore Type 검사", "Android는 'BKS' 유형 KeyStore만 허용합니다. 'BKS' 유형 키스토어를 사용하고 있는지 확인하십시오.:", ["KeyStore"])
		for keystore in list_Non_BKS_keystore:
			writer.show_Path(d, keystore)
	else:
		writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_INFO, "KeyStore Type 검사", "키 저장소 'BKS' type OK", ["KeyStore"])

	# ------------------------------------------------------------------------
	#Android PackageInfo signatures checking:

	"""
		Example:

		    move-result-object v0
		    iget-object v2, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

			PackageManager pkgManager = context.getPackageManager();
			pkgManager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES).signatures[0].toByteArray();
	"""

	list_PackageInfo_signatures = []
	path_PackageInfo_signatures = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/content/pm/PackageManager;", "getPackageInfo", "(Ljava/lang/String; I)Landroid/content/pm/PackageInfo;")
	path_PackageInfo_signatures = filteringEngine.filter_list_of_paths(d, path_PackageInfo_signatures)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_PackageInfo_signatures):
		if i.getResult()[2] is None:
			continue
		if i.getResult()[2] == 64:
			list_PackageInfo_signatures.append(i.getPath())

	if list_PackageInfo_signatures:
		writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_NOTICE, "서명 코드 가져오기 검사", 
			"이 앱은 코드에 패키지 서명을 확인하는 코드가 있습니다. 공격자들에 의해 앱이 해킹당했는지 확인하기 위해 사용될 수 있습니다.", ["Signature", "Hacker"])
		for signature in list_PackageInfo_signatures:
			writer.show_Path(d, signature)
	else:
		writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_INFO, "서명 코드 가져오기 검사", "이 앱이 코드에서 서명을 확인하는 것을 감지하지 못했습니다.", ["Signature", "Hacker"])

	# ------------------------------------------------------------------------
	#Developers preventing screenshot capturing checking:

	"""
		Example:
		    const/16 v1, 0x2000
		    invoke-super {p0, p1}, Landroid/support/v7/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V
		    invoke-virtual {p0}, Lcom/example/preventscreencapture/MainActivity;->getWindow()Landroid/view/Window;
		    move-result-object v0
		    invoke-virtual {v0, v1, v1}, Landroid/view/Window;->setFlags(II)V


			getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
	"""

	list_code_for_preventing_screen_capture = []
	path_code_for_preventing_screen_capture = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/view/Window;", "setFlags", "(I I)V")
	path_code_for_preventing_screen_capture = filteringEngine.filter_list_of_paths(d, path_code_for_preventing_screen_capture)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_code_for_preventing_screen_capture):
		if (i.getResult()[1] is None) or (i.getResult()[2] is None):
			continue
		if (not isinstance(i.getResult()[1], (int, long))) or (not isinstance(i.getResult()[2], (int, long))):
			continue
		if (i.getResult()[1] & 0x2000) and (i.getResult()[2] & 0x2000):
			list_code_for_preventing_screen_capture.append(i.getPath())

	if list_code_for_preventing_screen_capture:
		writer.startWriter("HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_NOTICE, "스크린샷 캡처 방지", 
			"""이 앱에는 캡처를 방지하는 코드가 설정되어 있습니다.
예시: getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
개발자가 앱을 보호하기 위해 사용합니다.:""", ["Hacker"])
		for interesting_code in list_code_for_preventing_screen_capture:
			writer.show_Path(d, interesting_code)
	else:
		writer.startWriter("HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_INFO, "스크린샷 캡처 방지", "이 앱에 스크린샷 캡처를 차단하는 코드 설정이 있는지 탐지하지 못했습니다.", ["Hacker"])


	# ------------------------------------------------------------------------
	#Runtime exec checking:

	"""
		Example Java code:
			1. Runtime.getRuntime().exec("");
			2. Runtime rr = Runtime.getRuntime(); Process p = rr.exec("ls -al");
		    
		Example Bytecode code (The same bytecode for those two Java code):
			const-string v2, "ls -al"
		    invoke-virtual {v1, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
	"""

	list_Runtime_exec = []

	path_Runtime_exec = vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/lang/Runtime;", "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
	path_Runtime_exec = filteringEngine.filter_list_of_paths(d, path_Runtime_exec)

	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_Runtime_exec):
		if i.getResult()[1] is None:
			continue
		if i.getResult()[1] == "su":
			list_Runtime_exec.append(i.getPath())

	if path_Runtime_exec:
		writer.startWriter("COMMAND", LEVEL_CRITICAL, "Runtime exec 검사", "이 앱은 critical한 함수 'Runtime.getRuntime().exec(\"...\")'를 사용하고있습니다.\n다음 코드 세션이 유해하지 않은지 확인하십시오:", ["Command"])

		writer.show_Paths(d, path_Runtime_exec)

		if list_Runtime_exec :
			writer.startWriter("COMMAND_SU", LEVEL_CRITICAL, "Runtime Critical Command 검사", "\"root\" 권한 코드 섹션 'Runtime.getRuntime(.exec(\"su\")'에 대한 요청 중입니다:", ["Command"])

			for path in list_Runtime_exec:
				writer.show_Path(d, path)
	else:
		writer.startWriter("COMMAND", LEVEL_INFO, "Runtime Command 검사", "이 앱은 critical한 함수 'Runtime.getRuntime().exec(\"...\")'를 사용하고 있지 않습니다.", ["Command"])

	# -------------------------------------------------------

	#HTTPS ALLOW_ALL_HOSTNAME_VERIFIER checking:

	"""
		Example Java code:
		    HttpsURLConnection.setDefaultHostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

		Example Bytecode code (The same bytecode for those two Java code):	
			(1)
			sget-object v11, Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;
	    	invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V
	    	
	    	(2)
		   	new-instance v11, Lcom/example/androidsslconnecttofbtest/MainActivity$2;
		    invoke-direct {v11, p0}, Lcom/example/androidsslconnecttofbtest/MainActivity$2;-><init>(Lcom/example/androidsslconnecttofbtest/MainActivity;)V
		    invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

		Scenario:
			https://www.google.com/  => Google (SSL certificate is valid, CN: www.google.com)
			https://60.199.175.18   => IP of Google (SSL certificate is invalid, See Chrome error message.
	"""

	# (1)inner class checking 

	# First, find out who calls it
	path_HOSTNAME_INNER_VERIFIER = vmx.get_tainted_packages().search_class_methods_exact_match("Ljavax/net/ssl/HttpsURLConnection;", "setDefaultHostnameVerifier", "(Ljavax/net/ssl/HostnameVerifier;)V")
	path_HOSTNAME_INNER_VERIFIER2 = vmx.get_tainted_packages().search_class_methods_exact_match("Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier", "(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V")
	path_HOSTNAME_INNER_VERIFIER.extend(path_HOSTNAME_INNER_VERIFIER2)

	path_HOSTNAME_INNER_VERIFIER = filteringEngine.filter_list_of_paths(d, path_HOSTNAME_INNER_VERIFIER)

	dic_path_HOSTNAME_INNER_VERIFIER_new_instance = filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(d, analysis, path_HOSTNAME_INNER_VERIFIER, 1)  #parameter index 1

	# Second, find the called custom classes
	list_HOSTNAME_INNER_VERIFIER = []

	methods_hostnameverifier = get_method_ins_by_implement_interface_and_method(d, ["Ljavax/net/ssl/HostnameVerifier;"], TYPE_COMPARE_ANY, "verify", "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z")
	for method in methods_hostnameverifier:
		register_analyzer = analysis.RegisterAnalyzerVM_ImmediateValue(method.get_instructions())
		if register_analyzer.get_ins_return_boolean_value():  #Has security problem
			list_HOSTNAME_INNER_VERIFIER.append(method)

	list_HOSTNAME_INNER_VERIFIER = filteringEngine.filter_list_of_methods(list_HOSTNAME_INNER_VERIFIER)

	if list_HOSTNAME_INNER_VERIFIER :

		output_string = """이 앱을 사용하면 자체 정의 호스트 이름 확인기가 모든 Common Names(CN)을 수락할 수 있습니다. 
이 취약성을 통해 공격자는 사용자가 모르게 유효한 인증서로 MITM 공격을 수행할 수 있습니다. 
사례: 
(1)http://osvdb.org/96411 
(2)http://www.wooyun.org/bugs/wooyun-2010-042710 
(3)http://www.wooyun.org/bugs/wooyun-2010-052339
Google 문서: http://developer.android.com/training/articles/security-ssl.html (주의: HostnameVerifier를 교체하는 것은 매우 위험할 수 있습니다). 
OWASP Mobile top 10개 문서: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

CN(Common Name) 인증의 중요도를 확인합니다.
Google Chrome을 사용하여 탐색:
 - https://www.google.com   => SSL 인증서가 유효함
 - https://60.199.175.158/  => Google.com의 IP 주소이지만 CN이 일치하지 않아 인증서가 유효하지 않습니다. Google.com으로 이동할 수 있지만 공격자와 일반 사용자를 구분할 수 없습니다.

다음 메서드의 코드를 확인하십시오.:"""

		writer.startWriter("SSL_CN1", LEVEL_CRITICAL, "SSL 구현 검사(사용자 지정 클래스에서 호스트 이름 확인)", output_string, ["SSL_Security"])


		for method in list_HOSTNAME_INNER_VERIFIER :
			writer.write(method.easy_print())

			# because one class may initialize by many new instances of it
			method_class_name = method.get_class_name()
			if method_class_name in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
				writer.show_Paths(d, dic_path_HOSTNAME_INNER_VERIFIER_new_instance[method_class_name])
	else :
		writer.startWriter("SSL_CN1", LEVEL_INFO, "SSL 구현 검사(사용자 지정 클래스에서 호스트  확인)", "자체 정의된 HOSTNAME VERIFIER 검사 확인.", ["SSL_Security"])


	# (2)ALLOW_ALL_HOSTNAME_VERIFIER fields checking

	if "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;" in dic_path_HOSTNAME_INNER_VERIFIER_new_instance :
		path_HOSTNAME_INNER_VERIFIER_new_instance = dic_path_HOSTNAME_INNER_VERIFIER_new_instance["Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"]
	else :
		path_HOSTNAME_INNER_VERIFIER_new_instance = None

	# "vmx.get_tainted_field" will return "None" if nothing found
	field_ALLOW_ALL_HOSTNAME_VERIFIER = vmx.get_tainted_field("Lorg/apache/http/conn/ssl/SSLSocketFactory;" ,"ALLOW_ALL_HOSTNAME_VERIFIER", "Lorg/apache/http/conn/ssl/X509HostnameVerifier;")

	if field_ALLOW_ALL_HOSTNAME_VERIFIER :
		filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = filteringEngine.filter_list_of_variables(d, field_ALLOW_ALL_HOSTNAME_VERIFIER.get_paths())
	else :
		filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = None

	if path_HOSTNAME_INNER_VERIFIER_new_instance or filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths :
		
		output_string = """이 앱을 사용하면 자체 정의 호스트 이름 확인기가 모든 Common Names(CN)을 수락할 수 있습니다. 
이 취약성을 통해 공격자는 사용자가 모르게 유효한 인증서로 MITM 공격을 수행할 수 있습니다. 
사례: 
(1)http://osvdb.org/96411 
(2)http://www.wooyun.org/bugs/wooyun-2010-042710 
(3)http://www.wooyun.org/bugs/wooyun-2010-052339
Google 문서: http://developer.android.com/training/articles/security-ssl.html (주의: HostnameVerifier를 교체하는 것은 매우 위험할 수 있습니다). 
OWASP Mobile top 10개 문서: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

CN(Common Name) 인증의 중요도를 확인합니다.
Google Chrome을 사용하여 탐색:
 - https://www.google.com   => SSL 인증서가 유효함
 - https://60.199.175.158/  => Google.com의 IP 주소이지만 CN이 일치하지 않아 인증서가 유효하지 않습니다. Google.com으로 이동할 수 있지만 공격자와 일반 사용자를 구분할 수 없습니다.

다음 메서드의 코드를 확인하십시오.:"""

		writer.startWriter("SSL_CN2", LEVEL_CRITICAL, "SSL 구현 검사(필드에서 호스트 이름 확인)", output_string, ["SSL_Security"])

		if filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths :
			"""
				Example code: 
				SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
				factory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
			"""

			for path in filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
				writer.show_single_PathVariable(d, path)

		if path_HOSTNAME_INNER_VERIFIER_new_instance :	
			"""
				Example code: 
				SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
				factory.setHostnameVerifier(new AllowAllHostnameVerifier());
			"""
			#For this one, the exclusion procedure is done on earlier
			writer.show_Paths(d, path_HOSTNAME_INNER_VERIFIER_new_instance)
	else :
		writer.startWriter("SSL_CN2", LEVEL_INFO, "SSL 구현 검사(필드에서 호스트 이름 확인)", "심각한 취약성 \"ALLOW_ALL_HOSTNAME_VERIFFER\" 필드 설정 또는 \"AllowAllHostnameVerifier\" 클래스 인스턴스를 찾을 수 없습니다.", ["SSL_Security"])

	# -------------------------------------------------------

	#SSL getInsecure

	list_getInsecure = []
	path_getInsecure = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/net/SSLCertificateSocketFactory;", "getInsecure", "(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;")
	path_getInsecure = filteringEngine.filter_list_of_paths(d, path_getInsecure)

	if path_getInsecure:

		output_string = """이 팩토리를 사용하여 만든 소켓(안전하지 않은 메서드 "getInsecure")은 man-in-the-middle attacks에 취약합니다. 
참조를 확인하십시오: http://developer.android.com/reference/android/net/SSLCertificateSocketFactory.html#getInsecure(int, android.net.SSLSessionCache). 
안전하지 않은 코드를 제거하십시오.:"""

		writer.startWriter("SSL_CN3", LEVEL_CRITICAL, "SSL 구현 검사(필드에서 호스트 이름 확인)", output_string, ["SSL_Security"])
		writer.show_Paths(d, path_getInsecure)
	else:
		writer.startWriter("SSL_CN3", LEVEL_INFO, "SSL 구현 검사(필드에서 호스트 이름 확인)", "안전하지 않은 메서드 \"getInsecure\"로 SSLocketFactory를 검색하지 못했습니다.", ["SSL_Security"])

	# -------------------------------------------------------

	#HttpHost default scheme "http"

	"""
		Check this paper to see why I designed this vector: "The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"


		Java Example code:
	    	HttpHost target = new HttpHost(uri.getHost(), uri.getPort(), HttpHost.DEFAULT_SCHEME_NAME);

	    Smali Example code:
	    	const-string v4, "http"
	    	invoke-direct {v0, v2, v3, v4}, Lorg/apache/http/HttpHost;-><init>(Ljava/lang/String; I Ljava/lang/String;)V
	"""

	list_HttpHost_scheme_http = []
	path_HttpHost_scheme_http = vmx.get_tainted_packages().search_class_methods_exact_match("Lorg/apache/http/HttpHost;", "<init>", "(Ljava/lang/String; I Ljava/lang/String;)V")
	path_HttpHost_scheme_http = filteringEngine.filter_list_of_paths(d, path_HttpHost_scheme_http)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_HttpHost_scheme_http):
		if i.getResult()[3] is None:
			continue
		if (i.is_string(i.getResult()[3])) and ((i.getResult()[3]).lower() == "http"):
			list_HttpHost_scheme_http.append(i.getPath())

	if list_HttpHost_scheme_http:
		writer.startWriter("SSL_DEFAULT_SCHEME_NAME", LEVEL_CRITICAL, "SSL 구현 검사(HttpHost)", 
			"이 앱은 \"HttpHost\"를 사용하지만 기본 체계는 \"Http\" 또는 \"HttpHost\"입니다.DEFAULT_SCHEME_NAME(http)\"입니다. \"https\"로 변경하십시오.:", ["SSL_Security"])

		for i in list_HttpHost_scheme_http:
			writer.show_Path(d, i)
	else:
		writer.startWriter("SSL_DEFAULT_SCHEME_NAME", LEVEL_INFO, "SSL 구현 검사(HttpHost)", "HttpHost위한 DEFAULT_SCHEME_NAME 검사: OK", ["SSL_Security"])

	# ------------------------------------------------------------------------
	#WebViewClient onReceivedSslError errors

	# First, find out who calls setWebViewClient
	path_webviewClient_new_instance = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/webkit/WebView;", "setWebViewClient", "(Landroid/webkit/WebViewClient;)V")
	dic_webviewClient_new_instance = filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(d, analysis, path_webviewClient_new_instance, 1)

	# Second, find which class and method extends it
	list_webviewClient = []
	methods_webviewClient = get_method_ins_by_superclass_and_method(d, ["Landroid/webkit/WebViewClient;"], "onReceivedSslError", "(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V")
	for method in methods_webviewClient:
		if is_kind_string_in_ins_method(method, "Landroid/webkit/SslErrorHandler;->proceed()V"):
			list_webviewClient.append(method)

	list_webviewClient = filteringEngine.filter_list_of_methods(list_webviewClient)

	if list_webviewClient :
		writer.startWriter("SSL_WEBVIEW", LEVEL_CRITICAL, "SSL 구현 검사(WebView위한 WebViewClient)", 
			"""SSL 인증서가 잘못된 경우에도 연결을 허용하는 확장 "WebViewClient"의 메서드 내에서 "handler.proceed();"를 사용하지 마십시오(MITM 취약성).
참조:
(1)WebView 공격: https://www.iseclab.org/papers/webview_leet13.pdf 
(2)OWASP Mobile Top 10 문서: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
(3)https://jira.appcelerator.org/browse/TIMOB-4488
취약한 코드:
""", ["SSL_Security"])

		for method in list_webviewClient :
			writer.write(method.easy_print())

			# because one class may initialize by many new instances of it
			method_class_name = method.get_class_name()
			if method_class_name in dic_webviewClient_new_instance:
				writer.show_Paths(d, dic_webviewClient_new_instance[method_class_name])

	else :
		writer.startWriter("SSL_WEBVIEW", LEVEL_INFO, "SSL 구현 검사(WebView위한 WebViewClient)", "\"WebViewClient\"(MITM 취약성)의 중요한 사용을 탐지하지 못했습니다.", ["SSL_Security"])


	# ------------------------------------------------------------------------
	#WebView setJavaScriptEnabled - Potential XSS:

	"""
		Java Example code:
	    	webView1 = (WebView)findViewById(R.id.webView1);
			webView1.setWebViewClient(new ExtendedWebView());
			WebSettings webSettings = webView1.getSettings();
			webSettings.setJavaScriptEnabled(true);

	    Smali Example code:
			const/4 v1, 0x1
    		invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
	"""

	list_setJavaScriptEnabled_XSS = []
	path_setJavaScriptEnabled_XSS = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V")
	path_setJavaScriptEnabled_XSS = filteringEngine.filter_list_of_paths(d, path_setJavaScriptEnabled_XSS)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_setJavaScriptEnabled_XSS):
		if i.getResult()[1] is None:
			continue
		if i.getResult()[1] == 0x1:
			list_setJavaScriptEnabled_XSS.append(i.getPath())

	if list_setJavaScriptEnabled_XSS:
		writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_WARNING, "WebView XSS 공격 검사", 
			"WebView에서 \"set JavaScriptEnabled(true)\"를 발견했으며 잠재적인 XSS 공격에 노출될 수 있습니다. 웹 페이지 코드를 주의 깊게 확인하고 출력을 삭제하십시오.", ["WebView"])
		for i in list_setJavaScriptEnabled_XSS:
			writer.show_Path(d, i)
	else:
		writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_INFO, "WebView XSS 공격 검사", "WebView에서 \"set JavaScriptEnabled(true)\"를 검색하지 못했습니다.", ["WebView"])

	# ------------------------------------------------------------------------
	#HttpURLConnection bug checking:

	"""
		Example Java code:
			private void disableConnectionReuseIfNecessary() {
				// Work around pre-Froyo bugs in HTTP connection reuse.
				if (Integer.parseInt(Build.VERSION.SDK) < Build.VERSION_CODES.FROYO) {
					System.setProperty("http.keepAlive", "false");
				}
			}

		Example Bytecode code:
			const-string v0, "http.keepAlive"
			const-string v1, "false"
			invoke-static {v0, v1}, Ljava/lang/System;->setProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

	"""

	if (int_min_sdk is not None) and (int_min_sdk <= 8):

		pkg_HttpURLConnection = vmx.get_tainted_packages().search_packages("Ljava/net/HttpURLConnection;")
		pkg_HttpURLConnection = filteringEngine.filter_list_of_paths(d, pkg_HttpURLConnection)

		#Check only when using the HttpURLConnection
		if pkg_HttpURLConnection:

			list_pre_Froyo_HttpURLConnection = []
			path_pre_Froyo_HttpURLConnection = vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/lang/System;", "setProperty", "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;")
			path_pre_Froyo_HttpURLConnection = filteringEngine.filter_list_of_paths(d, path_pre_Froyo_HttpURLConnection)

			has_http_keepAlive_Name = False
			has_http_keepAlive_Value = False

			for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_pre_Froyo_HttpURLConnection) :
				if (i.getResult()[0] == "http.keepAlive"):
					has_http_keepAlive_Name = True
					list_pre_Froyo_HttpURLConnection.append(i.getPath())	#Only list the "false" one
					if (i.getResult()[1] == "false"):
						has_http_keepAlive_Value = True
						break

			if has_http_keepAlive_Name:
				if has_http_keepAlive_Value:
					writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android 버그 검사", 
						"시스템 속성 \"HttpURLConnection\"에 대한 \"http.keepAlive\"가 올바르게 설정되었습니다.")

				else:
					output_string = """시스템 속성 "HttpURLConnection"를 설정해야 합니다."http.keepAlive"를 "false"으로 유지하다
"HttpURLConnection"을 사용하고 있습니다. 안드로이드 2.2(Froyo) 이전 버전에는 버그가 몇 가지 있습니다. 
특히 읽을 수 있는 InputStream에서 close()를 호출하면 연결 풀에 독이 발생할 수 있습니다. 연결 풀링을 사용하지 않도록 설정하여 이 문제를 해결하십시오.
참조를 확인하십시오.:
 (1)http://developer.android.com/reference/java/net/HttpURLConnection.html
 (2)http://android-developers.blogspot.tw/2011/09/androids-http-clients.html"""
					writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_NOTICE, "HttpURLConnection Android 버그 검사", output_string)

					writer.show_Paths(d, list_pre_Froyo_HttpURLConnection)     #Notice: list_pre_Froyo_HttpURLConnection
			else:
				output_string = """시스템 속성 "HttpURLConnection"를 설정해야 합니다."http.keepAlive"를 "false"으로 유지하다
"HttpURLConnection"을 사용하고 있습니다. 안드로이드 2.2(Froyo) 이전 버전에는 버그가 몇 가지 있습니다. 
특히 읽을 수 있는 InputStream에서 close()를 호출하면 연결 풀에 독이 발생할 수 있습니다. 연결 풀링을 사용하지 않도록 설정하여 이 문제를 해결하십시오.
참조를 확인하십시오.: 
 (1)http://developer.android.com/reference/java/net/HttpURLConnection.html
 (2)http://android-developers.blogspot.tw/2011/09/androids-http-clients.html"""

				writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_NOTICE, "HttpURLConnection Android 버그 검사", output_string)
				#Make it optional to list library
				writer.show_Paths(d, pkg_HttpURLConnection)   #Notice: pkg_HttpURLConnection

		else:
			writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android 버그 검사", 
						"\"HttpURLConnection\"를 사용하지 않기 떄문에 \"http.keepAlive\"검사를 무시합니다.")

	else:
		writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android Bug Checking", 
			"\"HttpURLConnection\"를 사용하지 않기 떄문에 \"http.keepAlive\"검사를 무시하고 Sdk의 8버전이상 입니다.")

	# ------------------------------------------------------------------------
	# SQLiteDatabase - beginTransactionNonExclusive() checking:

	if (int_min_sdk is not None) and (int_min_sdk < 11):
		
		path_SQLiteDatabase_beginTransactionNonExclusive = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/database/sqlite/SQLiteDatabase;", "beginTransactionNonExclusive", "()V")
		path_SQLiteDatabase_beginTransactionNonExclusive = filteringEngine.filter_list_of_paths(d, path_SQLiteDatabase_beginTransactionNonExclusive)

		if path_SQLiteDatabase_beginTransactionNonExclusive :
			output_string = StringHandler()
			output_string.append("\"SQLiteDatabase\"에서 \"beginTransactionNonExclusive\"를 사용 중이지만 minSdk는 " + str(int_min_sdk) + "아래를 지원합니다.")
			output_string.append("\"beginTransactionNonExclusive\"는 API < 11에서 지원되지 않습니다. 이전 버전의 Android에서 \"beginTransaction\"을 사용해야 합니다.")
			output_string.append("참조: http://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html#beginTransactionNonExclusive()")
			writer.startWriter("DB_DEPRECATED_USE1", LEVEL_CRITICAL, "SQLiteDatabase Transaction 반대 검사", output_string.get(), ["Database"])

			writer.show_Paths(d, path_SQLiteDatabase_beginTransactionNonExclusive)
		else:
			writer.startWriter("DB_DEPRECATED_USE1", LEVEL_INFO, "SQLiteDatabase Transaction 반대 검사", "\"SQLiteDatabase:beginTransactionNonExclusive\"을 사용하고 있지 않습니다.", ["Database"])
	else:
		writer.startWriter("DB_DEPRECATED_USE1", LEVEL_INFO, "SQLiteDatabase Transaction 반대 검사", "설정된 minSdk > = 11이므로 \"SQLiteDatabase:beginTransactionNonExclusive\" 검사를 무시합니다.", ["Database"])

	# ------------------------------------------------------------------------

	"""
		MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE checking:

		MODE_WORLD_READABLE = 1
		MODE_WORLD_WRITEABLE = 2
		MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE = 3

		http://jimmy319.blogspot.tw/2011/07/android-internal-storagefile-io.html

		Example Java Code:
			FileOutputStream outputStream = openFileOutput("Hello_World", Activity.MODE_WORLD_READABLE);

		Example Smali Code:
			const-string v3, "Hello_World"
			const/4 v4, 0x1
		    invoke-virtual {p0, v3, v4}, Lcom/example/android_mode_world_testing/MainActivity;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
	"""

	#Get a list of 'PathP' objects that are vulnerabilities
	list_path_openOrCreateDatabase = []
	list_path_openOrCreateDatabase2 = []
	list_path_getDir = []
	list_path_getSharedPreferences = []
	list_path_openFileOutput = []

	path_openOrCreateDatabase = vmx.get_tainted_packages().search_methods_exact_match("openOrCreateDatabase", "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;")
	path_openOrCreateDatabase = filteringEngine.filter_list_of_paths(d, path_openOrCreateDatabase)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_openOrCreateDatabase):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_openOrCreateDatabase.append(i.getPath())

	path_openOrCreateDatabase2 = vmx.get_tainted_packages().search_methods_exact_match("openOrCreateDatabase", "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory; Landroid/database/DatabaseErrorHandler;)Landroid/database/sqlite/SQLiteDatabase;")
	path_openOrCreateDatabase2 = filteringEngine.filter_list_of_paths(d, path_openOrCreateDatabase2)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_openOrCreateDatabase2):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_openOrCreateDatabase2.append(i.getPath())

	path_getDir = vmx.get_tainted_packages().search_methods_exact_match("getDir", "(Ljava/lang/String; I)Ljava/io/File;")
	path_getDir = filteringEngine.filter_list_of_paths(d, path_getDir)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_getDir):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_getDir.append(i.getPath())

	path_getSharedPreferences = vmx.get_tainted_packages().search_methods_exact_match("getSharedPreferences", "(Ljava/lang/String; I)Landroid/content/SharedPreferences;")
	path_getSharedPreferences = filteringEngine.filter_list_of_paths(d, path_getSharedPreferences)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_getSharedPreferences):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_getSharedPreferences.append(i.getPath())

	path_openFileOutput = vmx.get_tainted_packages().search_methods_exact_match("openFileOutput", "(Ljava/lang/String; I)Ljava/io/FileOutputStream;")
	path_openFileOutput = filteringEngine.filter_list_of_paths(d, path_openFileOutput)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_openFileOutput):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_openFileOutput.append(i.getPath())

	if list_path_openOrCreateDatabase or list_path_openOrCreateDatabase2 or list_path_getDir or list_path_getSharedPreferences or list_path_openFileOutput:

		writer.startWriter("MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_CRITICAL, "App Sandbox Permission 검사", 
			"보안 문제 \"MODE_WORLD_READABLE\" 또는 \"MODE_WORLD_WRITEABLE\"이(가) 발견되었습니다(참조: https://www.owasp.org/index.php/Mobile_Top_10_2014-M2):")

		if list_path_openOrCreateDatabase:
			writer.write("[openOrCreateDatabase - 3 params]")
			for i in list_path_openOrCreateDatabase:
				writer.show_Path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_openOrCreateDatabase2:
			writer.write("[openOrCreateDatabase - 4 params]")
			for i in list_path_openOrCreateDatabase2:
				writer.show_Path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_getDir:
			writer.write("[getDir]")
			for i in list_path_getDir:
				writer.show_Path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_getSharedPreferences:
			writer.write("[getSharedPreferences]")
			for i in list_path_getSharedPreferences:
				writer.show_Path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_openFileOutput:
			writer.write("[openFileOutput]")
			for i in list_path_openFileOutput:
				writer.show_Path(d, i)
			writer.write("--------------------------------------------------")

	else:
		writer.startWriter("MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_INFO, "App Sandbox Permission 검사", 
			"'openOrCreateDatabase', 'openOrCreateDatabase2', 'getDir', 'getSharedPreferences', 'openFileOutput'에서 보안 문제 \"MODE_WORLD_WRITETABLE\"를 찾을 수 없습니다.")

	# ------------------------------------------------------------------------
	#List all native method

	"""
		Example:
	    	const-string v0, "AndroBugsNdk"
	    	invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
	"""

	cm = d.get_class_manager()

	dic_NDK_library_classname_to_ndkso_mapping = {}
	list_NDK_library_classname_to_ndkso_mapping = []
	path_NDK_library_classname_to_ndkso_mapping = vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/lang/System;", "loadLibrary", "(Ljava/lang/String;)V")
	path_NDK_library_classname_to_ndkso_mapping = filteringEngine.filter_list_of_paths(d, path_NDK_library_classname_to_ndkso_mapping)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_NDK_library_classname_to_ndkso_mapping):
		if (i.getResult()[0] is None) or (not i.is_string(0)):
			continue
		so_file_name = i.getResult()[0]
		src_class_name, src_method_name, src_descriptor =  i.getPath().get_src(cm)
		if src_class_name is None:
			continue
		if src_class_name not in dic_NDK_library_classname_to_ndkso_mapping :
			dic_NDK_library_classname_to_ndkso_mapping[src_class_name] = []

		dic_NDK_library_classname_to_ndkso_mapping[src_class_name].append(toNdkFileFormat(str(i.getResult()[0])))
		list_NDK_library_classname_to_ndkso_mapping.append([toNdkFileFormat(str(i.getResult()[0])), i.getPath()])

	if list_NDK_library_classname_to_ndkso_mapping:
		writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_NOTICE, "기본 라이브러리 로드 검사", "네이티브 라이브러리 로드 코드(System.loadLibrary(...))가 발견되었습니다.:")

		for ndk_location , path in list_NDK_library_classname_to_ndkso_mapping:
			writer.write("[" + ndk_location + "]")
			writer.show_Path(d, path)
	else:
		writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_INFO, "기본 라이브러리 로드 검사", "로드된 기본 라이브러리가 없습니다.")

	dic_native_methods = {}
	regexp_sqlcipher_database_class = re.compile(".*/SQLiteDatabase;")
	for method in d.get_methods() :
		if method.is_native():
			class_name = method.get_class_name()
			if filteringEngine.is_class_name_not_in_exclusion(class_name) :
				if class_name not in dic_native_methods:
					dic_native_methods[class_name] = []
				dic_native_methods[class_name].append(method)

			# <<Essential_Block_1>>
			if regexp_sqlcipher_database_class.match(class_name) :
				if (method.get_name() == "dbopen") or (method.get_name() == "dbclose") :   #Make it to 2 conditions to add efficiency
					isUsingSQLCipher = True #This is for later use

	if dic_native_methods:

		if args.extra == 2 : #The output may be too verbose, so make it an option

			dic_native_methods_sorted = collections.OrderedDict(sorted(dic_native_methods.items()))

			writer.startWriter("NATIVE_METHODS", LEVEL_NOTICE, "기본 메서드 검사", "발견된 네이티브 메서드:")

			for class_name, method_names in dic_native_methods_sorted.items():
				if class_name in dic_NDK_library_classname_to_ndkso_mapping:
					writer.write("Class: %s (로드된 NDK 파일: %s)" % (class_name, dic_NDK_library_classname_to_ndkso_mapping[class_name]))
				else:
					writer.write("Class: %s" % (class_name))
				writer.write("   ->메서드:")
				for method in method_names:
					writer.write("        %s%s" % (method.get_name(), method.get_descriptor()))

	else:
		if args.extra == 2 : #The output may be too verbose, so make it an option
			writer.startWriter("NATIVE_METHODS", LEVEL_INFO, "기본 메서드 검사", "네이티브 메서드를 찾을 수 없습니다.")

	#Framework Detection: Bangcle

	is_using_Framework_Bangcle = False
	is_using_Framework_ijiami = False
	is_using_Framework_MonoDroid = False

	#Display only when using the Framework (Notice: This vector depends on "List all native method")
	if list_NDK_library_classname_to_ndkso_mapping :
		
		android_name_in_application_tag = a.get_android_name_in_application_tag()
		list_NDK_library_classname_to_ndkso_mapping_only_ndk_location = dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(list_NDK_library_classname_to_ndkso_mapping)

		if ("libsecexe.so" in list_NDK_library_classname_to_ndkso_mapping_only_ndk_location) :
			if (android_name_in_application_tag == "com.secapk.wrapper.ApplicationWrapper") :
				is_using_Framework_Bangcle = True
			else :
				path_secapk = vmx.get_tainted_packages().search_class_methods_exact_match("Lcom/secapk/wrapper/ACall;", "getACall", "()Lcom/secapk/wrapper/ACall;")
				if path_secapk :
					is_using_Framework_Bangcle = True

		if (len(list_NDK_library_classname_to_ndkso_mapping_only_ndk_location) == 2) :
			if ("libexec.so" in list_NDK_library_classname_to_ndkso_mapping_only_ndk_location) and ("libexecmain.so" in list_NDK_library_classname_to_ndkso_mapping_only_ndk_location) :
				paths_ijiami_signature = vmx.get_tainted_packages().search_class_methods_exact_match("Lcom/shell/NativeApplication;", "load", "(Landroid/app/Application; Ljava/lang/String;)Z")
				if paths_ijiami_signature :
					is_using_Framework_ijiami = True

		if (android_name_in_application_tag == "mono.android.app.Application") :
			for name, _, _ in a.get_files_information() :
				if (name == "lib/armeabi-v7a/libmonodroid.so") or (name == "lib/armeabi/libmonodroid.so") :
					is_using_Framework_MonoDroid = True
					break

		if is_using_Framework_Bangcle :
			writer.startWriter("FRAMEWORK_BANGCLE", LEVEL_NOTICE, "암호화 프레임워크 - Bangcle", 
				"이 앱은 Bangcle 암호화 프레임워크(http://www.bangcle.com/)를 사용하고 있습니다.", ["Framework"])
		if is_using_Framework_ijiami :
			writer.startWriter("FRAMEWORK_IJIAMI", LEVEL_NOTICE, "암호화 프레임워크 - Ijiami", 
				"이 앱은 Ijiami 암호화 프레임워크(http://www.ijiami.cn/)를 사용하고 있습니다.", ["Framework"])
	
	if is_using_Framework_MonoDroid :
		writer.startWriter("FRAMEWORK_MONODROID", LEVEL_NOTICE, "암호화 프레임워크 - MonoDroid", "이 앱은 MonoDroid 암호화 프레임워크(http://xamarin.com/android)를 사용하고 있습니다.", ["Framework"])
	else :
		writer.startWriter("FRAMEWORK_MONODROID", LEVEL_INFO, "암호화 프레임워크 - MonoDroid", " 앱은 MonoDroid 암호화 프레임워크(http://xamarin.com/android)를 사용하고 있지 않습니다.", ["Framework"])

	# ------------------------------------------------------------------------
	#Detect dynamic code loading

	paths_DexClassLoader = vmx.get_tainted_packages().search_methods( "Ldalvik/system/DexClassLoader;", ".", ".")
	paths_DexClassLoader = filteringEngine.filter_list_of_paths(d, paths_DexClassLoader)
	if paths_DexClassLoader:
		writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_WARNING, "동적 코드 로딩", "동적 코드 로드(DexClassLoader)가 발견되었습니다.")
		writer.show_Paths(d, paths_DexClassLoader)
	else:
		writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_INFO, "동적 코드 로딩", "동적 코드 로드(DexClassLoader)가 발견되지 않았습니다.")


	# ------------------------------------------------------------------------
	#Get External Storage Directory access invoke

	paths_ExternalStorageAccess = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/os/Environment;", "getExternalStorageDirectory", "()Ljava/io/File;")
	paths_ExternalStorageAccess = filteringEngine.filter_list_of_paths(d, paths_ExternalStorageAccess)
	if paths_ExternalStorageAccess:
		writer.startWriter("EXTERNAL_STORAGE", LEVEL_WARNING, "외부 스토리지 액세스", "외부 스토리지 액세스 발견(외부 스토리지에 중요한 파일을 쓰지 마십시오):")
		writer.show_Paths(d, paths_ExternalStorageAccess)
	else:
		writer.startWriter("EXTERNAL_STORAGE", LEVEL_INFO, "외부 스토리지 액세스", "외부 스토리지 액세스를 찾을 수 없습니다.")

	# ------------------------------------------------------------------------
	#Android Fragment Vulnerability (prior to Android 4.4)

	prog = re.compile("Landroid/support/v(\d*)/app/Fragment;")
	REGEXP_EXCLUDE_CLASSESd_fragment_class = re.compile("(Landroid/support/)|(Lcom/actionbarsherlock/)")
	list_Fragment = []
	has_any_fragment = False
	for cls in d.get_classes() :
		if (cls.get_superclassname() == "Landroid/app/Fragment;") or prog.match(cls.get_superclassname()) :
			if not REGEXP_EXCLUDE_CLASSESd_fragment_class.match(cls.get_name()) : 
				# Exclude the classes from library itself to make the finding more precise and to check the user really use fragment, not just include the libs
				has_any_fragment = True
				list_Fragment.append(cls.get_name())

	list_Fragment_vulnerability_NonMethod_classes = []
	list_Fragment_vulnerability_Method_OnlyReturnTrue_methods = []
	list_Fragment_vulnerability_Method_NoIfOrSwitch_methods = []

	list_Fragment = filteringEngine.filter_list_of_classes(list_Fragment)

	if list_Fragment:
		for cls in d.get_classes() :
			if (cls.get_superclassname() == "Landroid/preference/PreferenceActivity;") or (cls.get_superclassname() == "Lcom/actionbarsherlock/app/SherlockPreferenceActivity;") :
				boolHas_isValidFragment = False
				method_isValidFragment = None
				for method in cls.get_methods():
					if (method.get_name() == "isValidFragment") and (method.get_descriptor() == "(Ljava/lang/String;)Z") :
						boolHas_isValidFragment = True
						method_isValidFragment = method
						break
				if boolHas_isValidFragment :
					register_analyzer = analysis.RegisterAnalyzerVM_ImmediateValue(method_isValidFragment.get_instructions())
					if register_analyzer.get_ins_return_boolean_value():
						list_Fragment_vulnerability_Method_OnlyReturnTrue_methods.append(method_isValidFragment)
					else:
						if not register_analyzer.has_if_or_switch_instructions():  #do not have "if" or "switch" op in instructions of method
							list_Fragment_vulnerability_Method_NoIfOrSwitch_methods.append(method_isValidFragment)
				else :
					list_Fragment_vulnerability_NonMethod_classes.append(cls.get_name())

	list_Fragment_vulnerability_NonMethod_classes = filteringEngine.filter_list_of_classes(list_Fragment_vulnerability_NonMethod_classes)
	list_Fragment_vulnerability_Method_OnlyReturnTrue_methods = filteringEngine.filter_list_of_methods(list_Fragment_vulnerability_Method_OnlyReturnTrue_methods)
	list_Fragment_vulnerability_Method_NoIfOrSwitch_methods = filteringEngine.filter_list_of_methods(list_Fragment_vulnerability_Method_NoIfOrSwitch_methods)

	if list_Fragment_vulnerability_NonMethod_classes or list_Fragment_vulnerability_Method_OnlyReturnTrue_methods or list_Fragment_vulnerability_Method_NoIfOrSwitch_methods:
		
		output_string = """'Fragment' 혹은 'Fragment for ActionbarSherlock'는 안드로이드 4.4(API 19) 이전 버전에는 심각한 취약점이 있습니다. 
참조: 
(1)http://developer.android.com/reference/android/os/Build.VERSION_CODES.html#KITKAT 
(2)http://developer.android.com/reference/android/preference/PreferenceActivity.html#isValidFragment(java.lang.String) 
(3)http://stackoverflow.com/questions/19973034/isvalidfragment-android-api-19 
(4)http://securityintelligence.com/new-vulnerability-android-framework-fragment-injection/ 
(5)http://securityintelligence.com/wp-content/uploads/2013/12/android-collapses-into-fragments.pdf 
(6)https://cureblog.de/2013/11/cve-2013-6271-remove-device-locks-from-android-phone/ """

		writer.startWriter("FRAGMENT_INJECTION", LEVEL_CRITICAL, "Fragment 취약성 검사", output_string, None, "BID 64208, CVE-2013-6271")

		if list_Fragment_vulnerability_NonMethod_classes:
			if int_target_sdk >= 19:
				#You must override. Otherwise, it always throws Exception
				writer.write("Android 4.4에서 예외 발생을 방지하려면 모든 \"PreferenceActivity\" 클래스에서 'isValidFragment' 메서드를 재정의해야 합니다.")
				for i in list_Fragment_vulnerability_NonMethod_classes: #Notice: Each element in the list is NOT method, but String
					writer.write("    " + i)
			else:
				#You must override. Otherwise, it always throws Exception
				writer.write("\"PreferenceActivity\" 클래스는 'isValidFragment' 메서드를 재정의하지 않으므로 취약할 수 있습니다(기본 설정 활동에 조각을 로드하지 않은 경우에도 'isValidFragment' 메서드를 재정의하고 이후 변경 시 앱을 보호하려면 \"false\"만 반환하십시오).")
				for i in list_Fragment_vulnerability_NonMethod_classes: #Notice: Each element in the list is NOT method, but String
					writer.write("    " + i)

		if list_Fragment_vulnerability_Method_OnlyReturnTrue_methods:
			writer.write("'isValidFragment'를 재정의하고 해당 클래스에서 \"true\"만 반환합니다. 조각의 유효 여부를 확인하려면 \"if\" 조건을 사용해야 합니다.")
			writer.write("(예시 코드: http://stackoverflow.com/questions/19973034/isvalidfragment-android-api-19/20139823#20139823)")
			for method in list_Fragment_vulnerability_Method_OnlyReturnTrue_methods:
				writer.write("    " + method.easy_print())

		if list_Fragment_vulnerability_Method_NoIfOrSwitch_methods:
			writer.write("재정의된 'isValidFragment' 메서드 내에서 올바른 Fragment을 확인하십시오.")
			for method in list_Fragment_vulnerability_Method_NoIfOrSwitch_methods:
				writer.write("    " + method.easy_print())

		if list_Fragment:
			writer.write("모든 잠재적인 취약점 \"Fragment\":")
			for i in list_Fragment:
				writer.write("    " + i)

	else:
		writer.startWriter("FRAGMENT_INJECTION", LEVEL_INFO, "Fragment 취약성 검사", 
			"\"Fragment\"가 \"Preference Activity\" 또는 \"Sharlock Preference Activity\"에 동적으로 로드되는 취약성을 감지하지 못했습니다.", None, "BID 64208, CVE-2013-6271")

	# ------------------------------------------------------------------------
	#Find all "dangerous" permission

	"""
		android:permission
		android:readPermission (for ContentProvider)
		android:writePermission (for ContentProvider)
	"""
	
	#Get a mapping dictionary
	PermissionName_to_ProtectionLevel = a.get_PermissionName_to_ProtectionLevel_mapping()

	dangerous_custom_permissions = []
	for name, protectionLevel in PermissionName_to_ProtectionLevel.items():
		if protectionLevel == PROTECTION_DANGEROUS :	# 1:"dangerous"
			dangerous_custom_permissions.append(name)

	if dangerous_custom_permissions :

		writer.startWriter("PERMISSION_DANGEROUS", LEVEL_CRITICAL, "AndroidManifest 위험한 권한의 보호수준 검사",
			"""다음 클래스의 보호 수준은 "위험"하므로 다른 앱이 이 권한(AndroidManifest.xml)에 액세스할 수 있습니다. 
앱에서 "Android:protection"을 사용하여 권한을 선언해야 합니다."signature" 또는 "signatureOrSystem"의 수준"을 지정하여 다른 앱이 이 앱에 대한 메시지를 등록하고 받을 수 없도록 합니다. 
Android:protectionLevel="signature"는 권한을 요청한 앱이 권한을 선언한 애플리케이션과 동일한 인증서로 서명되어야 함을 보장합니다. 
일부 관련 사례를 확인하십시오.: http://www.wooyun.org/bugs/wooyun-2010-039697  
다음 권한을 변경하십시오.:""")

		for class_name in dangerous_custom_permissions :
			writer.write(class_name)

			who_use_this_permission = get_all_components_by_permission(a.get_AndroidManifest(), class_name)
			who_use_this_permission = collections.OrderedDict(sorted(who_use_this_permission.items()))
			if who_use_this_permission :
				for key, valuelist in who_use_this_permission.items() :
					for list_item in valuelist:
						writer.write("    -> used by (" + key + ")" + a.format_value(list_item))
	else :
		writer.startWriter("PERMISSION_DANGEROUS", LEVEL_INFO, "AndroidManifest 위험한 권한의 보호수준 검사",
			"\"위험한\" 보호 수준 사용자 지정 사용 권한을 찾을 수 없습니다(AndroidManifest.xml).")


	# ------------------------------------------------------------------------
	#Find all "normal" or default permission

	normal_or_default_custom_permissions = []
	for name, protectionLevel in PermissionName_to_ProtectionLevel.items():
		if protectionLevel == PROTECTION_NORMAL :	# 0:"normal" or not set
			normal_or_default_custom_permissions.append(name)

	if normal_or_default_custom_permissions :
		writer.startWriter("PERMISSION_NORMAL", LEVEL_WARNING, "AndroidManifest 일반 권한의 보호수준 검사",
			"""다음 클래스의 보호 수준은 "일반" 또는 기본값입니다(AndroidManifest.xml). 
앱에서 "Android:protection"을 사용하여 권한을 선언해야 합니다."signature" 또는 "signatureOrSystem"의 수준"을 지정하여 다른 앱이 이 앱에 대한 메시지를 등록하고 받을 수 없도록 합니다. 
Android:protectionLevel="signature"는 권한을 요청한 앱이 권한을 선언한 애플리케이션과 동일한 인증서로 서명되어야 함을 보장합니다. 
이러한 권한을 모두 내보내거나 "signature" 또는 "signatureOrSystem" 보호 수준으로 변경해야 합니다.""")
		for class_name in normal_or_default_custom_permissions :
			writer.write(class_name)
			who_use_this_permission = get_all_components_by_permission(a.get_AndroidManifest(), class_name)
			who_use_this_permission = collections.OrderedDict(sorted(who_use_this_permission.items()))
			if who_use_this_permission :
				for key, valuelist in who_use_this_permission.items() :
					for list_item in valuelist:
						writer.write("    -> used by (" + key + ") " + a.format_value(list_item))
	else :
		writer.startWriter("PERMISSION_NORMAL", LEVEL_INFO, "AndroidManifest 일반 권한의 보호수준 검사",
			"기본 또는 \"기본\" 보호 수준 사용자 지정 사용 권한을 찾을 수 없습니다(AndroidManifest.xml).")

	# ------------------------------------------------------------------------

	#Lost "android:" prefix in exported components

	list_lost_exported_components = []
	find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
	xml = a.get_AndroidManifest()
	for tag in find_tags:
		for item in xml.getElementsByTagName(tag) :
			name = item.getAttribute("android:name")
			exported = item.getAttribute("exported")
			if (not isNullOrEmptyString(name)) and (not isNullOrEmptyString(exported)) :
				list_lost_exported_components.append( (tag, name) )

	if list_lost_exported_components :
		writer.startWriter("PERMISSION_NO_PREFIX_EXPORTED", LEVEL_CRITICAL, "AndroidManifest 손실 접두사 검사",
			""""android:" 접두사(AndroidManifest.xml)를 추가하지 않은 내보낸 구성 요소를 찾았습니다. 
참조: (1)http://blog.curesec.com/article/blog/35.html
               (2)http://safe.baidu.com/2014-07/cve-2013-6272.html
               (3)http://blogs.360.cn/360mobile/2014/07/08/cve-2013-6272/""", None, "CVE-2013-6272")

		for tag, name in list_lost_exported_components :
			writer.write(("%10s => %s") % (tag, a.format_value(name)))

	else :
		writer.startWriter("PERMISSION_NO_PREFIX_EXPORTED", LEVEL_INFO, "AndroidManifest 손실 접두사 검사",
			"\"android:\"에 접두사를 추가하지 않은 내보낸 구성 요소가 없습니다.", None, "CVE-2013-6272")

	# ------------------------------------------------------------------------
	
	#"exported" checking (activity, activity-alias, service, receiver):

	"""
		Remember: Even if the componenet is protected by "signature" level protection,
		it still cannot receive the broadcasts from other apps if the component is set to [exported="false"].
	    ---------------------------------------------------------------------------------------------------

		Even if the component is exported, it still can be protected by the "android:permission", for example:
		
	    <permission
	        android:name="com.example.androidpermissionexported.PermissionControl"
	        android:protectionLevel="signature" >
	    </permission>
	    <receiver
	        android:name=".SimpleBroadcastReceiver"
	        android:exported="true"
	        android:permission="com.example.androidpermissionexported.PermissionControl" >
	        <intent-filter>
	            <action android:name="com.example.androidpermissionexported.PermissionTest" />
	            <category android:name="android.intent.category.DEFAULT" />
	        </intent-filter>
	    </receiver>

		Apps with the same signature(signed with the same certificate) can send and receive the broadcasts with each other.
		Conversely, apps that do not have the same signature cannot send and receive the broadcasts with each other.
		If the protectionLevel is "normal" or not set, then the sending and receiving of broadcasts are not restricted.
		
		Even if the Action is used by the app itself, it can still be initialized from external(3rd-party) apps 
		if the [exported="false"] is not specified, for example:
	    Intent intent = new Intent("net.emome.hamiapps.am.action.UPDATE_AM");
	    intent.setClassName("net.emome.hamiapps.am", "net.emome.hamiapps.am.update.UpdateAMActivity");
	    startActivity(intent);

	    ---------------------------------------------------------------------------------------

	    **[PERMISSION_CHECK_STAGE]:
	        (1)If android:permission not set => Warn it can be accessed from external
	        (2)If android:permission is set => 
	            Check its corresponding android:protectionLevel is "not set(default: normal)" or "normal" or "dangerous"=> Warn it can be accessed from external
	            If the corresponding permission tag is not found => Ignore

	            **If the names of all the Action(s) are prefixing with "com.android." or "android." =>  Notify with a low priority warning
	                <receiver android:name="jp.naver.common.android.billing.google.checkout.BillingReceiver">
	                    <intent-filter>
	                        <action android:name="com.android.vending.billing.IN_APP_NOTIFY" />
	                        <action android:name="com.android.vending.billing.RESPONSE_CODE" />
	                        <action android:name="com.android.vending.billing.PURCHASE_STATE_CHANGED" />
	                    </intent-filter>
	                </receiver>
	            **You need to consider the Multiple Intent, for example:
	                <receiver android:name=".service.push.SystemBroadcastReceiver">
	                    <intent-filter android:enabled="true" android:exported="false">
	                        <action android:name="android.intent.action.BOOT_COMPLETED" />
	                        <action android:name="android.net.conn.CONNECTIVITY_CHANGE" />
	                    </intent-filter>
	                    <intent-filter android:enabled="true" android:exported="false">
	                        <action android:name="android.intent.action.PACKAGE_REPLACED" />
	                        <data android:scheme="package" android:path="jp.naver.line.android" />
	                    </intent-filter>
	                </receiver>
	            **The preceding example: intent-filter is set incorrectly. intent-filter does not have the "android:exported" => Warn misconfiguration


	    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	    [REASON_REGION_1]
	    **If exported is not set, the protectionalLevel of android:permission is set to "normal" by default =>
	        1.It "cannot" be accessed by other apps on Android 4.2 devices 
	        2.It "can" be accessed by other apps on Android 4.1 devices 

	    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	    If it is receiver, service, activity or activity-alias, check if the exported is set:
	        exported="false" => No problem

	        exported="true" => Go to [PERMISSION_CHECK_STAGE]

	        exported is not set => 
	            If it has any intent-filter:
	                Yes => Go to [PERMISSION_CHECK_STAGE]
	                No  => If the intent-filter is not existed, it is exported="false" by default => X(Ignore)

	        **Main Problem: If it is still necessary to check the setting of "android:permission"


	    If it is provider, the intent-filter must not exist, so check if the exported is set:
	        ->[exported="true"] or [exported is not set] :

	            =>1.If [exported is not set] + [android:targetSdkVersion >= 17], add to the Warning List. Check the reason: [REASON_REGION_1]
	                It is suggested to add "exported" and tell the users that the default value is not the same among different platforms
	                => Check Google's document (The default value is "true" for applications that set either android:minSdkVersion or android:targetSdkVersion to "16" or lower. 
						For applications that set either of these attributes to "17" or higher, the default is "false". - http://developer.android.com/guide/topics/manifest/provider-element.html#exported)

	            =>2.[PERMISSION_CHECK_STAGE, and check "android:readPermission" and "android:writePermission", and check android:permission, android:writePermission, android:readPermission]
						=> If any of the corresponding setting for protectionLevel is not found ,then ignore it.
						   If any of the corresponding setting for protectionLevel is found, warn the users when the protectionLevel is "dangerous" or "normal".

	        ->exported="false": 
	            => X(Ignore)
	"""

	list_ready_to_check = []
	find_tags = ["activity", "activity-alias", "service", "receiver"]
	xml = a.get_AndroidManifest()
	for tag in find_tags:
		for item in xml.getElementsByTagName(tag) :
			name = item.getAttribute("android:name")
			exported = item.getAttribute("android:exported")
			permission = item.getAttribute("android:permission")
			has_any_actions_in_intent_filter = False
			if (not isNullOrEmptyString(name)) and (exported.lower() != "false") :

				is_ready_to_check = False
				is_launcher = False
				has_any_non_google_actions = False
				isSyncAdapterService = False
				for sitem in item.getElementsByTagName("intent-filter"):
					for ssitem in sitem.getElementsByTagName("action"):
						has_any_actions_in_intent_filter = True

						action_name = ssitem.getAttribute("android:name")
						if (not action_name.startswith("android.")) and (not action_name.startswith("com.android.")) :
							has_any_non_google_actions = True

						if (action_name == "android.content.SyncAdapter") :
							isSyncAdapterService = True

					for ssitem in sitem.getElementsByTagName("category"):
						category_name = ssitem.getAttribute("android:name")
						if category_name == "android.intent.category.LAUNCHER" :
							is_launcher = True

				# exported="true" or exported not set
				if exported == "" :
					if has_any_actions_in_intent_filter:
						#CHECK
						is_ready_to_check = True
						
				elif exported.lower() == "true" : #exported = "true"
					#CHECK
					is_ready_to_check = True

				if (is_ready_to_check) and (not is_launcher) :
					list_ready_to_check.append( (tag, a.format_value(name), exported, permission, has_any_non_google_actions, has_any_actions_in_intent_filter, isSyncAdapterService) )
	# ------------------------------------------------------------------------
#CHECK procedure
	list_implicit_service_components = []

	list_alerting_exposing_components_NonGoogle = []
	list_alerting_exposing_components_Google = []
	for i in list_ready_to_check :
		component = i[0]
		permission = i[3]
		hasAnyNonGoogleActions = i[4]
		has_any_actions_in_intent_filter = i[5]
		isSyncAdapterService = i[6]
		is_dangerous = False
		if permission == "" :	#permission is not set
			is_dangerous = True
		else :	#permission is set
			if permission in PermissionName_to_ProtectionLevel:
				protectionLevel = PermissionName_to_ProtectionLevel[permission]
				if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS) : 
					is_dangerous = True
			# else: #cannot find the mapping permission
			# 	is_dangerous = True

		if is_dangerous :
			if (component == "service") and (has_any_actions_in_intent_filter) and (not isSyncAdapterService):
				list_implicit_service_components.append(i[1])

			if hasAnyNonGoogleActions :
				if i not in list_alerting_exposing_components_NonGoogle :
					list_alerting_exposing_components_NonGoogle.append(i)
			else :
				if i not in list_alerting_exposing_components_Google :
					list_alerting_exposing_components_Google.append(i)


	if list_alerting_exposing_components_NonGoogle or list_alerting_exposing_components_Google :
		if list_alerting_exposing_components_NonGoogle:
			writer.startWriter("PERMISSION_EXPORTED", LEVEL_WARNING, "AndroidManifest Exported Components 검사",
				"""외부 애플리케이션의 작업(AndroidManifest.xml)을 수신하기 위해 "exported" 구성 요소(런처 제외)를 찾았습니다.
이러한 구성 요소는 다른 앱에서 초기화할 수 있습니다. 원하지 않는 경우 속성을 [exported="false"]에 추가하거나 수정해야 합니다.
"signature" 이상의 protectionLevel을 사용하여 사용자 지정 권한으로 보호하고 "android:permission" 속성에 지정할 수도 있습니다.""")

			for i in list_alerting_exposing_components_NonGoogle:
				writer.write(("%10s => %s") % (i[0], i[1]))

		if list_alerting_exposing_components_Google:
			writer.startWriter("PERMISSION_EXPORTED_GOOGLE", LEVEL_NOTICE, "AndroidManifest Exported Components 검사 2",
				"Google의 \"Android\" actions(AndroidManifest.xml)을 수신하기 위해 \"exported\" 구성요소(런처 제외)를 찾았습니다.:")

			for i in list_alerting_exposing_components_Google:
				writer.write(("%10s => %s") % (i[0], i[1]))
	else :
		writer.startWriter("PERMISSION_EXPORTED", LEVEL_INFO, "AndroidManifest Exported Components 검사",
			"Android 또는 외부 애플리케이션의 작업(AndroidManifest.xml)을 수신하기 위해 내보낸 구성 요소(런처 제외)가 없습니다.")

	# ------------------------------------------------------------------------
	#"exported" checking (provider):
	# android:readPermission, android:writePermission, android:permission
	list_ready_to_check = []

	xml = a.get_AndroidManifest()
	for item in xml.getElementsByTagName("provider") :
		name = item.getAttribute("android:name")
		exported = item.getAttribute("android:exported")

		if (not isNullOrEmptyString(name)) and (exported.lower() != "false") :
			#exported is only "true" or non-set
			permission = item.getAttribute("android:permission")
			readPermission = item.getAttribute("android:readPermission")
			writePermission = item.getAttribute("android:writePermission")
			has_exported = True if (exported != "") else False

			list_ready_to_check.append( (a.format_value(name), exported, permission, readPermission, writePermission, has_exported) )

	list_alerting_exposing_providers_no_exported_setting = []	#providers that Did not set exported
	list_alerting_exposing_providers = []	#provider with "true" exported
	for i in list_ready_to_check :   #only exist "exported" provider or not set
		exported = i[1]
		permission = i[2]
		readPermission = i[3]
		writePermission = i[4]
		has_exported = i[5]

		is_dangerous = False
		list_perm = []
		if permission != "" :
			list_perm.append(permission)
		if readPermission != "" :
			list_perm.append(readPermission)
		if writePermission != "" :
			list_perm.append(writePermission)

		if list_perm : #among "permission" or "readPermission" or "writePermission", any of the permission is set
			for self_defined_permission in list_perm:   #(1)match any (2)ignore permission that is not found
				if self_defined_permission in PermissionName_to_ProtectionLevel:
					protectionLevel = PermissionName_to_ProtectionLevel[self_defined_permission]
					if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS) : 
						is_dangerous = True
						break
			if (exported == "") and (int_target_sdk >= 17) and (is_dangerous) :	#permission is not set, it will depend on the Android system
				list_alerting_exposing_providers_no_exported_setting.append(i)

		else :  #none of any permission
			if exported.lower() == "true" :
				is_dangerous = True
			elif (exported == "") and (int_target_sdk >= 17) :	#permission is not set, it will depend on the Android system
				list_alerting_exposing_providers_no_exported_setting.append(i)

		if is_dangerous :
			list_alerting_exposing_providers.append(i)   #exported="true" and none of the permission are set => of course dangerous

	if list_alerting_exposing_providers or list_alerting_exposing_providers_no_exported_setting:
		if list_alerting_exposing_providers_no_exported_setting :   #providers that Did not set exported

			writer.startWriter("PERMISSION_PROVIDER_IMPLICIT_EXPORTED", LEVEL_CRITICAL, "AndroidManifest ContentProvider Exported 검사",
				""""exported" 된 속성(AndroidManifest.xml)을 명시적으로 지정하는 것이 좋습니다.
Android "android:targetSdkVersion" < 17의 경우 ContentProvider의 내보낸 값은 기본적으로 "true"입니다.
Android "android:targetSdkVersion" >= 17의 경우 ContentProvider의 내보낸 값은 기본적으로 "false"입니다.
즉, "android:exported"를 명시적으로 설정하지 않으면 ContentProvider가 Android < 4.2 기기에 노출됩니다.
공급자 권한을 [protectionalLevel="normal"]로 설정하더라도 기본 제약 조건으로 인해 Android >= 4.2 기기에서 다른 앱은 여전히 ​​액세스할 수 없습니다.
처음에 다른 앱에서 사용하도록 하려면 내보내기를 "true"로 설정하고("signature" protectionalLevel에 의해 보호됨 포함) 사용하지 않으려면 "false"로 설정하십시오.
이미 해당 "permission", "writePermission" 또는 "readPermission"을 "signature" protectionLevel 이상으로 설정했다면 "exported"를 "true"로 지정하십시오.
Android >= 4.2 기기에서 동일한 서명으로 서명된 다른 앱은 액세스할 수 없기 때문입니다.
참조: http://developer.android.com/guide/topics/manifest/provider-element.html#exported
취약한 ContentProvider 예시: 
  (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
  (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
  (3)http://www.wooyun.org/bugs/wooyun-2010-039169
""")

			for i in list_alerting_exposing_providers_no_exported_setting :
				writer.write(("%10s => %s") % ("provider", i[0]))

		if list_alerting_exposing_providers:  #provider with "true" exported and not enough permission protected on it

			writer.startWriter("PERMISSION_PROVIDER_EXPLICIT_EXPORTED", LEVEL_CRITICAL, "AndroidManifest ContentProvider Exported 검사",
				""""exported"된 ContentProvider를 찾았으므로 기기의 다른 앱이 액세스할 수 있습니다(AndroidManifest.xml). 속성을 [exported="false"]로 수정하거나 원하지 않는 경우 최소한 "signature" protectionalLevel 권한을 설정해야 합니다.
취약한 ContentProvider 예시: 
  (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
  (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
  (3)http://www.wooyun.org/bugs/wooyun-2010-039169""")
			for i in list_alerting_exposing_providers:
				writer.write(("%10s => %s") % ("provider", i[0]))

	else:
		writer.startWriter("PERMISSION_PROVIDER_IMPLICIT_EXPORTED", LEVEL_INFO, "AndroidManifest ContentProvider Exported 검사",
			"exported 된 \"ContentProvider\"를 찾을 수 없습니다(AndroidManifest.xml).")

	# ------------------------------------------------------------------------
	#intent-filter checking:

	"""
		Example misconfiguration:
			<receiver android:name=".service.push.SystemBroadcastReceiver">
	            <intent-filter android:enabled="true" android:exported="false">
	                <action android:name="android.intent.action.BOOT_COMPLETED" />
	                <action android:name="android.intent.action.USER_PRESENT" />
	            </intent-filter>
	            <intent-filter android:enabled="true" android:exported="false">
	            </intent-filter>
	        </receiver>

	    Detected1: <intent-filter android:enabled="true" android:exported="false">
	    Detected2: No actions in "intent-filter"
	"""

	find_tags = ["activity", "activity-alias", "service", "receiver"]
	xml = a.get_AndroidManifest()
	list_wrong_intent_filter_settings = []
	list_no_actions_in_intent_filter = []
	for tag in find_tags :
		for sitem in xml.getElementsByTagName(tag) :
			isDetected1 = False
			isDetected2 = False
			for ssitem in sitem.getElementsByTagName("intent-filter") :
				if (ssitem.getAttribute("android:enabled") != "") or (ssitem.getAttribute("android:exported") != "") :
					isDetected1 = True
				if len(sitem.getElementsByTagName("action")) == 0 :
					isDetected2 = True
			if isDetected1 :
				list_wrong_intent_filter_settings.append( (tag, sitem.getAttribute("android:name")) )
			if isDetected2 :
				list_no_actions_in_intent_filter.append( (tag, sitem.getAttribute("android:name")) )

	if list_wrong_intent_filter_settings or list_no_actions_in_intent_filter :
		if list_wrong_intent_filter_settings :
			writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_WARNING, "AndroidManifest \"intent-filter\" Settings 검사",
				"""이러한 구성요소(AndroidManifest.xml)의 "intent-filter" 구성이 잘못되었습니다.
"intent-filter" 구성에는 "android:exported" 또는 "android:enabled" 속성이 없어야 합니다.
참조: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
""")
			for tag, name in list_wrong_intent_filter_settings :
				writer.write(("%10s => %s") % (tag, a.format_value(name)))

		if list_no_actions_in_intent_filter :
			writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_CRITICAL, "AndroidManifest \"intent-filter\" Settings 검사",
				"""이러한 구성요소(AndroidManifest.xml)의 "intent-filter" 구성이 잘못되었습니다.
 "intent-filter"에는 하나 이상의 "액션"이 있어야 합니다.
참조: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
""")
			for tag, name in list_no_actions_in_intent_filter :
				writer.write(("%10s => %s") % (tag, a.format_value(name)))
	else :
		writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_INFO, "AndroidManifest \"intent-filter\" Settings 검사",
			"AndroidManifest.xml의 \"intent-filter\"를 확인했습니다.")

	# ------------------------------------------------------------------------
	#Implicit Service (** Depend on: "exported" checking (activity, activity-alias, service, receiver) **)

	if list_implicit_service_components :
		writer.startWriter("PERMISSION_IMPLICIT_SERVICE", LEVEL_CRITICAL, "암묵적 서비스 검사",
			"""앱의 보안을 위해 서비스를 시작할 때 항상 명시적 의도를 사용하고 서비스에 대한 의도 필터를 선언하지 마십시오. 암묵적 의도를 사용하여 서비스를 시작하면 어떤 서비스가 의도에 응답할지 확신할 수 없고 사용자는 어떤 서비스가 시작되는지 볼 수 없기 때문에 보안 위험이 있습니다. 
Reference: http://developer.android.com/guide/components/intents-filters.html#Types""", ["Implicit_Intent"])

		for name in list_implicit_service_components :
			writer.write(("=> %s") % (a.format_value(name)))

	else :
		writer.startWriter("PERMISSION_IMPLICIT_SERVICE", LEVEL_INFO, "암묵적 서비스 검사",
			"위험한 암시적 서비스가 없습니다.", ["Implicit_Intent"])

	# ------------------------------------------------------------------------
	#SQLite databases

	is_using_android_dbs = vmx.get_tainted_packages().has_android_databases(filteringEngine.get_filtering_regexp())
	if is_using_android_dbs :
		if int_min_sdk < 15 :
			writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_NOTICE, "Android SQLite 데이터베이스 취약성 검사",
				"""이 앱은 Android SQLite 데이터베이스를 사용합니다.
Android 4.0 이전 버전에서는 SQLite Journal 정보 노출 취약성이 있습니다.
그러나 안드로이드 > 4.0으로 업그레이드한 사용자만 해결할 수 있으며 혼자 해결할 수 없습니다(단, "SQL Cipher" 또는 다른 lib로 데이터베이스 및 저널 암호화를 사용할 수 있습니다).
참조:
(1) http://blog.watchfire.com/files/androidsqlitejournal.pdf 
(2) http://www.youtube.com/watch?v=oCXLHjmH5rY """, ["Database"], "CVE-2011-3901")
		else :
			writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_NOTICE, "Android SQLite 데이터베이스 취약성 검사",
				"이 앱은 Android SQLite 데이터베이스를 사용하고 있습니다. 그러나 SQLite Journal 정보 노출 취약성에 시달리지 않습니다.", ["Database"], "CVE-2011-3901")
	else :
		writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_INFO, "Android SQLite 데이터베이스 취약성 검사",
			"이 앱은 Android SQLite 데이터베이스를 사용하지 않습니다.", ["Database"], "CVE-2011-3901")

	# ------------------------------------------------------------------------
	#Checking whether the app is using SQLCipher:
	#Reference to <<Essential_Block_1>>
	if isUsingSQLCipher :
		writer.startWriter("DB_SQLCIPHER", LEVEL_NOTICE, "Android SQLite 데이터베이스 암호화 (SQLCipher)",
			"이 앱은 SQLCipher(http://sqlcipher.net/)를 사용하여 데이터베이스를 암호화하거나 암호 해독합니다.", ["Database"])

		path_sqlcipher_dbs = vmx.get_tainted_packages().search_sqlcipher_databases()	#Don't do the exclusion checking on this one because it's not needed

		if path_sqlcipher_dbs :
			#Get versions:
			has_version1or0 = False
			has_version2 = False
			for _, version in path_sqlcipher_dbs :
				if version == 1 :
					has_version1or0 = True
				if version == 2 :
					has_version2 = True

			if has_version1or0 :
				writer.write("It's using \"SQLCipher for Android\" (Library version: 1.X or 0.X), package name: \"info.guardianproject.database\"")
			if has_version2 :
				writer.write("It's using \"SQLCipher for Android\" (Library version: 2.X or higher), package name: \"net.sqlcipher.database\"")

			#Dumping:
			for db_path, version in path_sqlcipher_dbs :
				writer.show_Path(d, db_path)

	else :
		writer.startWriter("DB_SQLCIPHER", LEVEL_INFO, "Android SQLite 데이터베이스 암호화 (SQLCipher)",
			"이 앱은 SQLCipher(http://sqlcipher.net/)를 사용하여 데이터베이스를 암호화하거나 암호 해독하지 않습니다.", ["Database"])

	# ------------------------------------------------------------------------
	#Find "SQLite Encryption Extension (SEE) on Android"
	has_SSE_databases = False
	for cls in d.get_classes() :
		if cls.get_name() == "Lorg/sqlite/database/sqlite/SQLiteDatabase;" :	#Don't do the exclusion checking on this one because it's not needed
			has_SSE_databases = True
			break

	if has_SSE_databases :
		writer.startWriter("DB_SEE", LEVEL_NOTICE, "Android SQLite 데이터베이스 암호화 (SQLite Encryption Extension (SEE))",
			"이 앱은 Android(http://www.sqlite.org/android)에서 SQLite Encryption Extension(SEE)을 사용하여 데이터베이스를 암호화하거나 암호 해독합니다.", ["Database"])
	
	else :
		writer.startWriter("DB_SEE", LEVEL_INFO, "Android SQLite 데이터베이스 암호화 (SQLite Encryption Extension (SEE))",
			"이 앱은 Android(http://www.sqlite.org/android)에서 데이터베이스를 암호화하거나 암호 해독하기 위해 SQLite Encryption Extension(SEE)을 사용하지 않습니다.", ["Database"])

	# ------------------------------------------------------------------------
	#Searching SQLite "PRAGMA key" encryption:
	result_sqlite_encryption = efficientStringSearchEngine.get_search_result_by_match_id("$__sqlite_encryption__")
	result_sqlite_encryption = filteringEngine.filter_efficient_search_result_value(result_sqlite_encryption)
	if result_sqlite_encryption :
		writer.startWriter("HACKER_DB_KEY", LEVEL_NOTICE, "Android SQLite 데이터베이스 암호화용 키",
			"SQLite 데이터베이스를 암호화하기 위해 대칭 키(PRAGMA 키)를 사용한 것을 찾았습니다", ["Database", "Hacker"])

		for found_string, method in result_sqlite_encryption :
			writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())
	else :
		writer.startWriter("HACKER_DB_KEY", LEVEL_INFO, "Android SQLite 데이터베이스 암호화용 키",
			"SQLite 데이터베이스를 암호화하기 위해 대칭 키(PRAGMA 키)를 사용하는 것을 찾지 못했습니다(사용할 수도 있지만 찾지 못했습니다).", ["Database", "Hacker"])

	# ------------------------------------------------------------------------
	#Searching checking root or not:
	result_possibly_check_root = efficientStringSearchEngine.get_search_result_by_match_id("$__possibly_check_root__")
	result_possibly_check_su = efficientStringSearchEngine.get_search_result_by_match_id("$__possibly_check_su__")
	result_possibly_root_total = []

	if result_possibly_check_root :
		result_possibly_root_total.extend(result_possibly_check_root)

	if result_possibly_check_su :
		result_possibly_root_total.extend(result_possibly_check_su)

	result_possibly_root_total = filteringEngine.filter_efficient_search_result_value(result_possibly_root_total)

	if result_possibly_root_total :
		writer.startWriter("COMMAND_MAYBE_SYSTEM", LEVEL_NOTICE, "\"root\" 또는 시스템 권한 실행 검사", 
			"앱에는 \"root\" 권한, 마운트 파일 시스템 작업 또는 모니터링 시스템에 대한 코드 검사가 있을 수 있습니다.", ["Command"])

		list_possible_root = []
		list_possible_remount_fs = []
		list_possible_normal = []

		for found_string, method in set(result_possibly_root_total) :  #strip the duplicated items
			if ("'su'" == found_string) or ("/su" in found_string) :
				list_possible_root.append( (found_string, method, True) ) #3rd parameter: show string or not
			elif "mount" in found_string : #mount, remount
				list_possible_remount_fs.append( (found_string, method, True) )
			else :
				list_possible_normal.append( (found_string, method, True) )

		lst_ordered_finding = []
		lst_ordered_finding.extend(list_possible_root)
		lst_ordered_finding.extend(list_possible_remount_fs)
		lst_ordered_finding.extend(list_possible_normal)

		for found_string, method, show_string in lst_ordered_finding :
			if show_string :
				writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor() + "  => " + found_string)
			else :
				writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())
	else :

		writer.startWriter("COMMAND_MAYBE_SYSTEM", LEVEL_INFO, "\"root\" 또는 시스템 권한 실행 검사", 
			"\"root\" 권한(su)을 확인하거나 시스템 권한을 얻는 코드를 찾지 못했습니다(아직 찾지 못했을 가능성이 있음).", ["Command"])

	# ------------------------------------------------------------------------
	#Android getting IMEI, Android_ID, UUID problem

	path_Device_id = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/telephony/TelephonyManager;", "getDeviceId", "()Ljava/lang/String;")
	path_Device_id = filteringEngine.filter_list_of_paths(d, path_Device_id)

	if path_Device_id:

		writer.startWriter("SENSITIVE_DEVICE_ID", LEVEL_WARNING, "IMEI 및 Device ID 가져오기", 
			"""이 앱에는 "device ID(IMEI)"를 가져오는 코드가 있지만 이 "TelephonyManager.getDeviceId()" 접근 방식에는 문제가 있습니다.
1. 비 전화: 전화 통신 하드웨어가 없는 Wi-Fi 전용 장치 또는 음악 플레이어에는 이러한 종류의 고유 식별자가 없습니다.
2. 지속성: 이 기능이 있는 기기에서는 기기 데이터 삭제 및 공장 초기화 후에도 지속됩니다. 이 상황에서 앱이 이를 동일한 장치로 간주해야 하는지 여부는 전혀 명확하지 않습니다.
3. 권한: READ_PHONE_STATE 권한이 필요합니다. 
4. 버그: 구현에 버그가 있고 가비지(예: 0 또는 별표)를 반환하는 프로덕션 전화기의 몇 가지 인스턴스를 보았습니다.
장치의 고유 ID를 얻으려면 다음 문서에서 "설치" 프레임워크를 사용하는 것이 좋습니다.
참조: http://android-developers.blogspot.tw/2011/03/identifying-app-installations.html
""", ["Sensitive_Information"])

		writer.show_Paths(d, path_Device_id)

	else:

		writer.startWriter("SENSITIVE_DEVICE_ID", LEVEL_INFO, "IMEI 및 Device ID 가져오기", 
			"이 앱이 \"TelephonyManager.getDeviceId()\" 접근 방식으로 \"Device ID(IMEI)\"를 가져오는 것을 감지하지 못했습니다.", ["Sensitive_Information"])

	# ------------------------------------------------------------------------
	#Android "android_id"

	path_android_id = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/provider/Settings$Secure;", "getString", "(Landroid/content/ContentResolver; Ljava/lang/String;)Ljava/lang/String;")
	path_android_id = filteringEngine.filter_list_of_paths(d, path_android_id)

	list_android_id = []
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_android_id) :
		if i.getResult()[1] is None:
			continue
		if i.getResult()[1] == "android_id":
			list_android_id.append(i.getPath())

	if list_android_id:		
		writer.startWriter("SENSITIVE_SECURE_ANDROID_ID", LEVEL_WARNING, "ANDROID_ID 가져오기", 
			"""이 앱에는 64비트 숫자 "Settings.Secure.ANDROID_ID"를 가져오는 코드가 있습니다.
ANDROID_ID는 고유한 기기 식별자에 적합합니다. 하지만 단점이 있습니다. 먼저 Android 2.2(Froyo) 이전 릴리스에서는 100% 신뢰할 수 없습니다.
또한 모든 인스턴스에 동일한 ANDROID_ID가 있는 주요 개발업체의 인기 있는 handset에 널리 관찰된 버그가 하나 이상 있었습니다.
장치의 고유 ID를 얻으려면 다음 문서에서 "Installation" 프레임워크를 사용하는 것이 좋습니다.
참조: http://android-developers.blogspot.tw/2011/03/identifying-app-installations.html 
""", ["Sensitive_Information"])

		for path in list_android_id :
			writer.show_Path(d, path)
	else:

		writer.startWriter("SENSITIVE_SECURE_ANDROID_ID", LEVEL_INFO, "ANDROID_ID 가져오기", 
			"이 앱이 64비트의 번호 \"Settings.Secure.ANDROID_ID\"를 가져오는 것을 감지하지 못했습니다.", ["Sensitive_Information"])

	# ------------------------------------------------------------------------
	#Checking sending SMS code

	"""
	  Example:
		Landroid/telephony/SmsManager;->sendDataMessage(Ljava/lang/String; Ljava/lang/String; S [B Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
		Landroid/telephony/SmsManager;->sendMultipartTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;)V
		Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
	"""

	list_sms_signatures = [ 
		("sendDataMessage", "(Ljava/lang/String; Ljava/lang/String; S [B Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"),
		("sendMultipartTextMessage", "(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;)V"),
		("sendTextMessage", "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V")
	]

	path_sms_sending = vmx.get_tainted_packages().search_class_methodlist_exact_match("Landroid/telephony/SmsManager;", list_sms_signatures)
	path_sms_sending = filteringEngine.filter_list_of_paths(d, path_sms_sending)

	if path_sms_sending:
		writer.startWriter("SENSITIVE_SMS", LEVEL_WARNING, "SMS 전송 코드", 
			"이 앱에는 SMS 메시지를 보내기 위한 코드가 있습니다. (sendDataMessage, sendMultipartTextMessage or sendTextMessage):")
		writer.show_Paths(d, path_sms_sending)
	else:
		writer.startWriter("SENSITIVE_SMS", LEVEL_INFO, "SMS 전송 코드", 
			"이 앱에 SMS 메시지를 보내기 위한 코드가 있음을 감지하지 못했습니다. (sendDataMessage, sendMultipartTextMessage or sendTextMessage).")

	# ------------------------------------------------------------------------
	#Checking shared_user_id

	sharedUserId = a.get_shared_user_id()
	sharedUserId_in_system = False

	if (sharedUserId == "android.uid.system") :
		sharedUserId_in_system = True
		
	if sharedUserId_in_system :
		writer.startWriter("SHARED_USER_ID", LEVEL_NOTICE, "AndroidManifest sharedUserId 검사", 
			"이 앱은 \"system(uid=1000)\" 권한이 필요한 \"android.uid.system\" sharedUserId를 사용합니다. 사용자의 기기에 성공적으로 설치하려면 개발업체의 키 저장소 또는 Google의 키 저장소로 서명해야 합니다.", ["System"])
	else :
		writer.startWriter("SHARED_USER_ID", LEVEL_INFO, "AndroidManifest sharedUserId 검사", 
			"이 앱은 \"android.uid.system\" sharedUserId를 사용하지 않습니다.", ["System"])

	# System shared_user_id + Master Key Vulnerability checking: (Depends on "Master Key Vulnerability checking")
	if sharedUserId_in_system and isMasterKeyVulnerability :
		writer.startWriter("MASTER_KEY_SYSTEM_APP", LEVEL_CRITICAL, "Master Key 취약점이 있는 루팅 시스템", 
			"이 앱은 Master Key 취약점이 있는 \"system(uid=1000)\" 권한을 요청하여 기기를 루팅시키는 악성코드가 있습니다.")

	# ------------------------------------------------------------------------
	#File delete alert

	path_FileDelete = vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/io/File;", "delete", "()Z")
	path_FileDelete = filteringEngine.filter_list_of_paths(d, path_FileDelete)

	if path_FileDelete :
		writer.startWriter("FILE_DELETE", LEVEL_NOTICE, "File Unsafe Delete 검사", 
			"""삭제한 모든 항목은 사용자나 공격자, 특히 루팅된 기기에 의해 복구될 수 있습니다.
필수 파일을 삭제하기 위해 "file.delete()"를 사용하지 마십시오.
이 비디오를 확인하십시오: https://www.youtube.com/watch?v=tGw1fxUD-uY""")
		writer.show_Paths(d, path_FileDelete)
	else :
		writer.startWriter("FILE_DELETE", LEVEL_INFO, "File Unsafe Delete 검사", 
			"파일을 안전하지 않게 삭제하고 있음을 감지하지 못했습니다.")

	# ------------------------------------------------------------------------
	#Check if app check for installing from Google Play

	path_getInstallerPackageName = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/content/pm/PackageManager;", "getInstallerPackageName", "(Ljava/lang/String;)Ljava/lang/String;")
	path_getInstallerPackageName = filteringEngine.filter_list_of_paths(d, path_getInstallerPackageName)

	if path_getInstallerPackageName :
		writer.startWriter("HACKER_INSTALL_SOURCE_CHECK", LEVEL_NOTICE, "APK Installing Source 검사", 
			"이 앱에는 코드 검사 APK 설치 프로그램 소스(예: Google Play, Amazon 등)가 있습니다. 앱이 공격자에 의해 해킹되었는지 확인하는 데 사용할 수 있습니다.", ["Hacker"])
		writer.show_Paths(d, path_getInstallerPackageName)
	else :
		writer.startWriter("HACKER_INSTALL_SOURCE_CHECK", LEVEL_INFO, "APK Installing Source 검사", 
			"이 앱이 APK 설치 프로그램 소스를 검사하는 것을 감지하지 못했습니다.", ["Hacker"])

	# ------------------------------------------------------------------------
	#WebView setAllowFileAccess:

	"""
		Get all "dst" class: Landroid/webkit/WebSettings;
		  => Categorized by src function,
		     If the src function:
		       1.setAllowFileAccess does not exist    OR
		       2.setAllowFileAccess(true)
		           =>src function may be vulnerable

		**Why check WebSettings? It's because WebView almost always uses the method: WebView->getSettings()

		**Even if the below example, it will finally call WebSettings:
		  class TestWebView extends WebView {
		    public TestWebView(Context context) {
		      super(context);
		    }
		  }
	"""

	pkg_WebView_WebSettings = vmx.get_tainted_packages().search_packages("Landroid/webkit/WebSettings;")
	pkg_WebView_WebSettings = filteringEngine.filter_list_of_paths(d, pkg_WebView_WebSettings)

	dict_WebSettings_ClassMethod_to_Path = {}

	for path in pkg_WebView_WebSettings :
		src_class_name, src_method_name, src_descriptor =  path.get_src(cm)
		dst_class_name, dst_method_name, dst_descriptor =  path.get_dst(cm)

		dict_name = src_class_name + "->" + src_method_name + src_descriptor
		if dict_name not in dict_WebSettings_ClassMethod_to_Path :
			dict_WebSettings_ClassMethod_to_Path[dict_name] = []
		
		dict_WebSettings_ClassMethod_to_Path[dict_name].append( (dst_method_name + dst_descriptor, path) )


	path_setAllowFileAccess_vulnerable_ready_to_test = []
	path_setAllowFileAccess_confirm_vulnerable_src_class_func = []

	for class_fun_descriptor, value in dict_WebSettings_ClassMethod_to_Path.items() :
		has_Settings = False
		for func_name_descriptor, path in value :
			if func_name_descriptor == "setAllowFileAccess(Z)V" :
				has_Settings = True

				# Add ready-to-test Path list
				path_setAllowFileAccess_vulnerable_ready_to_test.append(path)
				break

		if not has_Settings :
			# Add vulnerable Path list
			path_setAllowFileAccess_confirm_vulnerable_src_class_func.append( class_fun_descriptor )


	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_setAllowFileAccess_vulnerable_ready_to_test):
		if (i.getResult()[1] == 0x1): # setAllowFileAccess is true

			path = i.getPath()
			src_class_name, src_method_name, src_descriptor =  path.get_src(cm)
			dict_name = src_class_name + "->" + src_method_name + src_descriptor

			if dict_name not in path_setAllowFileAccess_confirm_vulnerable_src_class_func :
				path_setAllowFileAccess_confirm_vulnerable_src_class_func.append( dict_name )

	if path_setAllowFileAccess_confirm_vulnerable_src_class_func :

		path_setAllowFileAccess_confirm_vulnerable_src_class_func = sorted(set(path_setAllowFileAccess_confirm_vulnerable_src_class_func))

		writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_WARNING, "WebView 로컬 파일 액세스 공격 검사", 
			"""WebView에서 "setAllowFileAccess(true)"를 찾거나 설정되지 않았습니다(기본적으로 사용 가능). 공격자는 WebView에 악의적인 스크립트를 주입하고 로컬 리소스에 액세스할 수 있는 기회를 이용할 수 있습니다. 이 문제는 로컬 파일 시스템 액세스를 비활성화하여 완화하거나 방지할 수 있습니다. (기본적으로 사용 가능)
이렇게 하면 파일 시스템 액세스만 활성화되거나 비활성화됩니다. 자산 및 리소스는 file:///android_asset 및 file:///android_res를 사용하여 계속 액세스할 수 있습니다.
공격자는 "mWebView.loadUrl("file:///data/data/[Your_Package_Name]/[File]");"을 사용하여 앱의 로컬 파일에 액세스할 수 있습니다.
참조: (1)https://labs.mwrinfosecurity.com/blog/2012/04/23/adventures-with-android-webviews/
      (2)http://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess(boolean)
WebView에 "yourWebView.getSettings().setAllowFileAccess(false)"를 추가하거나 수정하십시오.:
""", ["WebView"])
		for i in path_setAllowFileAccess_confirm_vulnerable_src_class_func :
			writer.write(i)

	else :
		writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_INFO, "WebView 로컬 파일 액세스 공격 검사", 
			"잠재적으로 중요한 로컬 파일 액세스 설정을 찾지 못했습니다.", ["WebView"])

	# ------------------------------------------------------------------------
	#Adb Backup check

	if a.is_adb_backup_enabled() :
		writer.startWriter("ALLOW_BACKUP", LEVEL_NOTICE, "AndroidManifest Adb Backup 검사", 
			"""이 앱에 대해 ADB Backup이 활성화됩니다(기본값: 활성화됨). ADB Backup은 모든 파일을 Backup할 수 있는 좋은 도구입니다. 이 앱에 대해 열려 있는 경우 휴대전화를 가진 사람들이 휴대전화에서 이 앱에 대한 모든 민감한 데이터를 복사할 수 있습니다(전제 조건: 1.휴대전화 화면 잠금 해제 2. 개발자 모드를 엽니다). 민감한 데이터에는 평생 액세스 토큰, 사용자 이름 또는 비밀번호 등이 포함될 수 있습니다.
ADB Backup 관련 보안 사례:
1.http://www.securityfocus.com/archive/1/530288/30/0/threaded
2.http://blog.c22.cc/advisories/cve-2013-5112-evernote-android-insecure-storage-of-pin-data-bypass-of-pin-protection/
3.http://nelenkov.blogspot.co.uk/2012/06/unpacking-android-backups.html
참조: http://developer.android.com/guide/topics/manifest/application-element.html#allowbackup
""")
	else :
		writer.startWriter("ALLOW_BACKUP", LEVEL_INFO, "AndroidManifest Adb Backup 검사", 
			"이 앱은 Adb Backup을 비활성화했습니다.")

	# ------------------------------------------------------------------------
	#SSL Verification Fail (To check whether the code verifies the certificate)

	methods_X509TrustManager_list = get_method_ins_by_implement_interface_and_method_desc_dict(d, ["Ljavax/net/ssl/X509TrustManager;"], TYPE_COMPARE_ANY, 
		["getAcceptedIssuers()[Ljava/security/cert/X509Certificate;", 
		 "checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V",
		 "checkServerTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"])

	list_X509Certificate_Critical_class = []
	list_X509Certificate_Warning_class = []

	for class_name, method_list in methods_X509TrustManager_list.items() :
		ins_count = 0

		for method in method_list :
			for ins in method.get_instructions() :
				ins_count = ins_count + 1

		if ins_count <= 4 :
			#Critical
			list_X509Certificate_Critical_class.append(class_name)
		else :
			#Warning
			list_X509Certificate_Warning_class.append(class_name)

	if list_X509Certificate_Critical_class or list_X509Certificate_Warning_class :

		log_level = LEVEL_WARNING
		log_partial_prefix_msg = "이 앱이 SSL 인증서의 유효성을 확인하는 조건이 있는지 확인하십시오. 제대로 확인하지 않으면 SSL 연결에 대해 자체 서명, 만료 또는 불일치 CN 인증서를 허용할 수 있습니다."

		if list_X509Certificate_Critical_class :
			log_level = LEVEL_CRITICAL
			log_partial_prefix_msg = "이 앱은 SSL 인증서의 유효성을 확인하지 않습니다. SSL 연결을 위해 자체 서명, 만료 또는 불일치 CN 인증서를 허용합니다."

		list_X509Certificate_merge_list = []
		list_X509Certificate_merge_list.extend(list_X509Certificate_Critical_class)
		list_X509Certificate_merge_list.extend(list_X509Certificate_Warning_class)

		dict_X509Certificate_class_name_to_caller_mapping = {}

		for method in d.get_methods() :
			for i in method.get_instructions():   # method.get_instructions(): Instruction
				if i.get_op_value() == 0x22 :  # 0x22 = "new-instance"
					if i.get_string() in list_X509Certificate_merge_list :
						referenced_class_name = i.get_string()
						if referenced_class_name not in dict_X509Certificate_class_name_to_caller_mapping :
							dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name] = []

						dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name].append(method)

		writer.startWriter("SSL_X509", log_level, "SSL 인증서 확인 검사", 
			log_partial_prefix_msg + """
이것은 critical한 취약점이며 공격자가 사용자 모르게 MITM 공격을 수행할 수 있도록 합니다
사용자의 사용자 이름이나 비밀번호를 전송하는 경우 이러한 민감한 정보가 누출될 수 있습니다.
참조:
(1)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
(2)Android Security book: http://goo.gl/BFb65r 
(3)https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=134807561
"X509Certificate"를 생성하고 "checkClientTrusted", "checkServerTrusted" 및 "getAcceptedIssuers" 기능을 빈 구현으로 재정의하지 마십시오.
자체 X509Certificate 클래스를 만드는 대신 기존 API를 사용하는 것이 좋습니다.
이 취약한 코드를 수정하거나 제거하십시오: 
""", ["SSL_Security"])
		if list_X509Certificate_Critical_class :
			writer.write("[Confirm Vulnerable]")
			for name in list_X509Certificate_Critical_class :
				writer.write("=> " + name)
				if name in dict_X509Certificate_class_name_to_caller_mapping :
					for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
						writer.write("      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())

		if list_X509Certificate_Warning_class :
			writer.write("--------------------------------------------------")
			writer.write("[Maybe Vulnerable (Please manually confirm)]")
			for name in list_X509Certificate_Warning_class :
				writer.write("=> " + name)
				if name in dict_X509Certificate_class_name_to_caller_mapping :
					for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
						writer.write("      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())

	else :
		writer.startWriter("SSL_X509", LEVEL_INFO, "SSL 인증서 확인 검사", 
				"취약한 X509Certificate 코드를 찾지 못했습니다.", ["SSL_Security"])

	#----------------------------------------------------------------
	#Must complete the last writer

	writer.completeWriter()

	writer.writeInf_ForceNoPrint("vector_total_count", writer.get_total_vector_count())

	#----------------------------------------------------------------
	#End of Checking

	#StopWatch
	now = datetime.now()
	stopwatch_total_elapsed_time = now - stopwatch_start
	stopwatch_analyze_time = now - analyze_start 
	stopwatch_loading_vm = analyze_start - stopwatch_start

	writer.writeInf_ForceNoPrint("time_total", stopwatch_total_elapsed_time.total_seconds())
	writer.writeInf_ForceNoPrint("time_analyze", stopwatch_analyze_time.total_seconds())
	writer.writeInf_ForceNoPrint("time_loading_vm", stopwatch_loading_vm.total_seconds())

	writer.update_analyze_status("success")
	writer.writeInf_ForceNoPrint("time_finish_analyze", datetime.utcnow())


def __persist_db(writer, args) :
	
	# starting_dvm
	# starting_androbugs

	if platform.system().lower() == "windows" :
		db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
	else :
		db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

	if not os.path.isfile(db_config_file) :
		print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
		traceback.print_exc()

	configParser = SafeConfigParser()
	configParser.read(db_config_file)

	MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
	MongoDB_Port = configParser.getint('DB_Config', 'MongoDB_Port')
	MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')

	Collection_Analyze_Result = configParser.get('DB_Collections', 'Collection_Analyze_Result')
	Collection_Analyze_Success_Results = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results')
	Collection_Analyze_Success_Results_FastSearch = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results_FastSearch')
	Collection_Analyze_Fail_Results = configParser.get('DB_Collections', 'Collection_Analyze_Fail_Results')

	from pymongo import MongoClient
	client = MongoClient(MongoDB_Hostname, MongoDB_Port)
	db = client[MongoDB_Database]	# Name is case-sensitive

	analyze_status = writer.get_analyze_status()

	try :

		if analyze_status is not None :
			#You might not get Package name when in "starting_apk" stage

			packed_analyzed_results = writer.get_packed_analyzed_results_for_mongodb()	# "details" will only be shown when success
			packed_analyzed_results_fast_search = writer.get_search_enhanced_packed_analyzed_results_for_mongodb()	# specifically designed for Massive Analysis

			collection_AppInfo = db[Collection_Analyze_Result]		# Name is case-sensitive
			collection_AppInfo.insert(packed_analyzed_results)
			
			if analyze_status == "success" :	#save analyze result only when successful
				collection_AnalyzeSuccessResults = db[Collection_Analyze_Success_Results]
				collection_AnalyzeSuccessResults.insert(packed_analyzed_results)

				collection_AnalyzeSuccessResultsFastSearch = db[Collection_Analyze_Success_Results_FastSearch]
				collection_AnalyzeSuccessResultsFastSearch.insert(packed_analyzed_results_fast_search)

		if (analyze_status == "fail") :
			collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]		# Name is case-sensitive
			collection_AnalyzeExceptions.insert(writer.getInf())

	# pymongo.errors.BulkWriteError, pymongo.errors.CollectionInvalid, pymongo.errors.CursorNotFound, pymongo.errors.DocumentTooLarge, pymongo.errors.DuplicateKeyError, pymongo.errors.InvalidOperation
	except Exception as err:
		try :
			writer.update_analyze_status("fail")
			writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

			writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
			writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
			writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
			writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

			packed_analyzed_results = writer.getInf()
			"""
				http://stackoverflow.com/questions/5713218/best-method-to-delete-an-item-from-a-dict
				There's also the minor point that .pop will be slightly slower than the del since it'll translate to a function call rather than a primitive.
				packed_analyzed_results.pop("details", None)	#remove the "details" tag, if the key is not found => return "None"
			"""
			if "details" in packed_analyzed_results :	#remove "details" result to prevent the issue is generating by the this item
				del packed_analyzed_results["details"]

			collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]		# Name is case-sensitive
			collection_AnalyzeExceptions.insert(packed_analyzed_results)
		except :
			if DEBUG :
				print("[Error on writing Exception to MongoDB]")
				traceback.print_exc()


def get_hash_scanning(writer) :
	# signature = hash(package_name(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
	# use "-" because aaa-bbb.com is not a valid domain name
	tmp_original = writer.getInf("package_name", "pkg") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(time.time()) + "-" + str(random.randrange(10000000, 99999999))
	tmp_hash = hashlib.sha512(tmp_original).hexdigest()
	return tmp_hash

def get_hash_exception(writer) :
	# signature = hash(analyze_error_id(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
	tmp_original = writer.getInf("analyze_error_id", "err") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(time.time()) + "-" + str(random.randrange(10000000, 99999999))
	tmp_hash = hashlib.sha512(tmp_original).hexdigest()
	return tmp_hash

def __persist_file(writer, args) :

	package_name =  writer.getInf("package_name")
	signature_unique_analyze =  writer.getInf("signature_unique_analyze")

	if package_name and signature_unique_analyze :
		return writer.save_result_to_file(os.path.join(args.report_output_dir, package_name + "_" + signature_unique_analyze + ".txt"), args)
	else :
		print("\"package_name\" or \"signature_unique_analyze\" not exist.")
		return False


def main() :

	args = parseArgument()

	writer = Writer()

	try :

		#Print Title
		writer.writePlainInf("""*************************************************************************
**   AndroBugs Framework - Android App Security Vulnerability Scanner  **
**                            version: 1.0.0                           **
**     author: Yu-Cheng Lin (@AndroBugs, http://www.AndroBugs.com)     **
**               contact: androbugs.framework@gmail.com                **
*************************************************************************""")

		#Analyze
		__analyze(writer, args)

		analyze_signature = get_hash_scanning(writer)
		writer.writeInf_ForceNoPrint("signature_unique_analyze", analyze_signature)	#For uniquely distinguish the analysis report
		writer.append_to_file_io_information_output_list("Analyze Signature: " + analyze_signature)
		writer.append_to_file_io_information_output_list("------------------------------------------------------------------------------------------------")

	except ExpectedException as err_expected :

		writer.update_analyze_status("fail")

		writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
		writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
		writer.writeInf_ForceNoPrint("analyze_error_id", err_expected.get_err_id())
		writer.writeInf_ForceNoPrint("analyze_error_message", err_expected.get_err_message())

		writer.writeInf_ForceNoPrint("signature_unique_analyze", get_hash_scanning(writer))	#For uniquely distinguish the analysis report
		writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

		if DEBUG :
			print(err_expected)

	except BadZipfile as zip_err :	#This may happen in the "a = apk.APK(apk_Path)"

		writer.update_analyze_status("fail")

		#Save the fail message to db
		writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

		writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
		writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
		writer.writeInf_ForceNoPrint("analyze_error_id", "fail_to_unzip_apk_file")
		writer.writeInf_ForceNoPrint("analyze_error_message", str(zip_err))

		writer.writeInf_ForceNoPrint("signature_unique_analyze", get_hash_scanning(writer))		#For uniquely distinguish the analysis report
		writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

		if DEBUG :
			print("[Unzip Error]")
			traceback.print_exc()

	except Exception as err :

		writer.update_analyze_status("fail")

		#Save the fail message to db
		writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

		writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
		writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
		writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
		writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

		writer.writeInf_ForceNoPrint("signature_unique_analyze", get_hash_scanning(writer))	#For uniquely distinguish the analysis report
		writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

		if DEBUG :
			traceback.print_exc()

	#Save to the DB
	if args.store_analysis_result_in_db :
		__persist_db(writer, args)


	if writer.get_analyze_status() == "success" :

		if REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_PRINT :
			writer.show(args)
		elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE :
			__persist_file(writer, args)	#write report to "disk"
		elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_PRINT_AND_FILE :
			writer.show(args)
			__persist_file(writer, args)	#write report to "disk"


if __name__ == "__main__":
	main()


"""
	Packages do not check:
		java
		android
		com.google
		org.apache
		org.json
		org.xml
"""
	
