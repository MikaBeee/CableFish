import os

class Solutionbuilder():
    def buildSSHlogfiles(self):
        sshdirpath = "Loggers/SshLogs"
        if os.path.exists(sshdirpath):
            pass
        else:
            os.makedirs(sshdirpath)
    
    def buildAPIConfigFile(self):
        apiconfigpath = "config.txt"

        if os.path.exists(apiconfigpath):
            return
        else:
            open(apiconfigpath, 'w').close()
          
