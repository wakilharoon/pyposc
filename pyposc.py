import sys
import os
import socket
import threading
import re
import time
from queue import Queue
from pyfiglet import Figlet
from termcolor import colored

os.system("color")
socket.setdefaulttimeout(1)
queue = Queue()
open_ports = 0

def welcome():
	f = Figlet("5lineoblique")
	print(colored(f.renderText("pyposc"), "cyan")) 
	print(colored(":::> pyposc :::> Created by Haroon :::> Version: 1.3 :::>", "yellow"))

def error_message():
	print(colored("[-] Invalid input", "red"))

def correct_input(user_input, pattern, seperator = None):
	entities = [x.strip() for x in user_input.split(seperator)]
	for entity in entities:
		if not re.fullmatch(pattern, entity):
			error_message()
			return False
	return entities

def get_target():
	ip_pattern = r"\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b"
	while True:
		user_input = input("\n[*] Enter target IP address: ")
		if not correct_input(user_input, ip_pattern):
			continue
		return correct_input(user_input, ip_pattern)[0]

def get_ports():
	port_pattern = r"([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
	while True:
		user_input = input("[*] Enter port(s): ")
		if "," in user_input:
			if not correct_input(user_input, port_pattern, ","):
				continue
			for port in correct_input(user_input, port_pattern, ","):
				queue.put(int(port))
			break
		elif "-" in user_input:
			if not correct_input(user_input, port_pattern, "-"):
				continue
			for port in range(int(correct_input(user_input, port_pattern, "-")[0]), int(correct_input(user_input, port_pattern, "-")[1]) + 1):
				queue.put(port)
			break
		else:
			if not correct_input(user_input, port_pattern):
				continue
			queue.put(int(correct_input(user_input, port_pattern)[0]))
			break

def get_threads():
	while True:
		user_input = input("[*] Enter number of threads to use (1 - 1000): ")
		try:
			user_input = int(user_input)
			if 1 <= user_input <= 1000:
				return user_input
			else:
				print(colored("[-] Number of threads must be between 1 and 1000", "red"))
		except:
			error_message()

def scan_port(ip_address):
	while not queue.empty():
		port = queue.get()
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((ip_address, port))
			s.close()
			try:
				service = socket.getservbyport(port)
			except:
				service = "unknown"
			print(colored(f"[+] Port {port} is open: {service}", "green"))
			global open_ports
			open_ports += 1
		except:
			pass

try:
	welcome()
	target = get_target()
	get_ports()
	num_of_ports = queue.qsize()
	num_of_threads = get_threads()
	print(colored(f"\n[*] Scanning {target}", "cyan"))
	thread_list = []
	for t in range(num_of_threads):
		thread = threading.Thread(target = scan_port, args = (target,))
		thread.start()
		thread_list.append(thread)
	start = time.perf_counter()
	for thread in thread_list:
		thread.join()
	end = time.perf_counter()
	scan_time = end - start
	print(colored(f"[*] Scanned {num_of_ports} ports in {scan_time:0.1f} seconds. Found {open_ports} open ports", "cyan"))
except KeyboardInterrupt:
	sys.exit(0)
