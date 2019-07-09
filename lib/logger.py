from time import gmtime, strftime

colour_red = "\033[1;31m"
colour_blue = "\033[1;34m"
colour_green = "\033[1;32m"
colour_yellow = "\033[1;33m"
colour_purple = "\033[1;35m"
colour_remove= "\033[0m"
bold = '\033[1m'


good='[+]'
bad='[!]'
info='[#]'
verb='[*]'

spacing=' '*5

VERBOSE=False

def BOLD(string):
	return (bold + string + colour_remove)

def RED(string):
	return (colour_red + string + colour_remove)

def BLUE(string):
	return (colour_blue + string + colour_remove)

def GREEN(string):
	return (colour_green + string + colour_remove)

def YELLOW(string):
	return (colour_yellow + string + colour_remove)

def blue(string):
	t=strftime("%H:%M:%S", gmtime())
	print '['+BLUE(t)+']'+spacing+string

def green(string):
	t=strftime("%H:%M:%S", gmtime())
	print '['+GREEN(t)+']'+spacing+string

def red(string):
	t=strftime("%H:%M:%S", gmtime())
	print '['+RED(t)+']'+spacing+string

def verbose(string):
	t=strftime("%H:%M:%S", gmtime())
	if VERBOSE == True:
		print '['+YELLOW(t)+']'+spacing+string

def header():
	print BOLD('Time') + ' '*11+ BOLD('Status')