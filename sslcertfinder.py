from subprocess import *
import re
import argparse
import sys

# Class to help colorize the output
#    This will be a module soon :)
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    N = '\033[1;44m'

# Main functions are cool
def main():

    #Get cert name from args
    parser = argparse.ArgumentParser()
    parser.add_argument('cert_name', type=str, help='Get int certs recursively')
    arg = parser.parse_args()

    # Get name of public key file
    #get_cert = input(bcolors.HEADER + 'Enter the cert name please: ' + bcolors.ENDC)
    get_cert = str(arg.cert_name)

    # store intermediate chain in variable chain
    chain = get_dc(get_cert)

    # combine content of all intermediate cert files
    #     into one convenient file
    combine_certs(chain)

# Function to do most of the work:
def get_dc(cert):

    # A list of the intermediate certs we find
    cert_list = []

    # Check the file type with a subprocess
    #     and the 'file' bash cmd
    check = check_output('file ' + cert, shell=True)

    check = str(check)
    check = check.rstrip('\\n\'').split(' ')

    # Convert file if it needs it
    if('data' in check):
        print('{warn}This file needs to be converted!!!{end}\n'.format(
            warn=bcolors.WARNING,
            end=bcolors.ENDC
        ))
        cert = cert.strip('\'')

        # Use openssl to convert the cert into the corrct format
        #    Thanks Winter!
        call('openssl x509 -inform der -in {cert} -out {cert}'.format(cert=cert), stderr=STDOUT, shell=True)
        check = str(check)
        check = re.findall(r'[^\[\]\.\"\',:b]', check)
        check = ''.join(check)
        check = check.split(' ')

        print('{warn}Format of file {check1} was {check2}{end}\n'.format(
            warn=bcolors.WARNING,
            check1=str(check[0]),
            check2=str(check[1]),
            end=bcolors.ENDC
        ))
        print('{ok}File has been converted: {end}'.format(
            ok=bcolors.OKGREEN,
            end=bcolors.ENDC
        ))
        check = call('file ' + cert, stderr=STDOUT, shell=True)
        check = str(check)
        print('\n')

    print('{ok}Searching for link in the file...{end}\n'.format(
        ok=bcolors.OKBLUE,
        end=bcolors.ENDC
    ))


    # Use openssl to find the next intermediate cert link form within
    #     the preceding file. Thanks Winter!
    response = check_output('openssl x509 -in {cert} -text -noout | grep \'CA Issuers\'; exit 0'.format(
        cert=cert),
        stderr=STDOUT,
        shell=True
    )
    response = str(response)
    response = response.strip('\n')
    link = re.findall('URI:(.*)', response.rstrip('\\n\''))


    # Let's get recursive!
    if(link):
        link = str(link).strip('[]')
        print('{ok}I found a link! :){link}{end}\n'.format(
            ok=bcolors.OKGREEN,
            link=link,
            end=bcolors.ENDC
        ))
        print('{ok}Let\'s download the next cert!{end}\n'.format(
            ok=bcolors.OKGREEN,
            end=bcolors.ENDC
        ))

        next_link = re.findall(r'[^/.*]+\.crt', link)
        next_link = str(next_link)
        next_link = next_link.strip('[]')
        print('{ok}Next link in the chain: {end}\n{next_link}'.format(
            ok=bcolors.OKBLUE,
            end=bcolors.ENDC,
            next_link=next_link
        ))
        call('wget -A.crt ' + link + ';exit 0', stderr=STDOUT, shell=True)
        cert_list.append(next_link)

        get_dc(next_link)
    else:
        print('{ok}No link : Must be root or super trustworthy :){end}'.format(
            ok=bcolors.OKGREEN,
            end=bcolors.ENDC
        ))

    return cert_list

# One intermediate .crt file to rule them all
def combine_certs(chain):
    for c in chain:
            c = c.strip('\'')
            infile = open(c, 'r')
            outfile = open('intermediate_chain.crt', 'a')

            line = infile.readline()

            while(len(line)>0):
                outfile.write(line)
                line = infile.readline()
            infile.close()
            outfile.close()

    print('{ok}\nHere are the certs we found and the order we found them:{end}'.format(
        ok=bcolors.OKBLUE,
        end=bcolors.ENDC
    ))
    i = 0
    index = len(chain) - (len(chain) - i)
    while(i < len(chain)):
        print('{inc}: {chainindex}'.format(
            inc=str(i + 1),
            chainindex=chain[index]
        ))
        i = i + 1

    print('\n{n}Certs have been combined into a file named intermediate_chain.crt{end}'.format(
        n=bcolors.N,
        end=bcolors.ENDC
    ))

# Programs like us...Baby we were born to run.
if __name__ == '__main__':
    main()
