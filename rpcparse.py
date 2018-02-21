def parsenum(s,num):
    result=0
    #num*=2
    for i in range(0,num):
        result=result*16+s[i]
    return result
def getint(s):
    return parsenum(s,4)
def getshort(s):
    return parsenum(s,2)
def getstring(s):
    return str(s)
def getbool(s):
    return (s==1) or (s==b"\x01")