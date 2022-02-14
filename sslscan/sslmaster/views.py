
from asyncio.windows_events import NULL
import whois
import dns.resolver
from django.http import HttpResponseRedirect
from django.shortcuts import render
from OpenSSL.SSL import Connection, Context, SSLv3_METHOD, TLSv1_2_METHOD
from datetime import datetime
import socket
from .models import Dataobject, Dataobjectdns, Dataobjectwhois,Hostnameentry,Hostnameentrywhois,Hostnameentrydns


def add_show(request):
    hostnames=[]
    temp_hostname=Hostnameentry.objects.all()
    for j in temp_hostname:
        hostnames.append(j.hostname)

    if 'delete' in request.POST:
        delhost=(request.POST.get('addhost',False)).strip()
        if delhost in hostnames:
            del_data=Hostnameentry.objects.get(hostname=delhost)
            del_data.delete()
        else:
            pass##########console handle     
        return HttpResponseRedirect('/')
    
    elif 'add' in request.POST:
        host=(request.POST.get('addhost',False)).strip()
        if host in hostnames:
            pass
        elif len(host)==0 :
            pass
        else:
            insert=Hostnameentry(hostname=host,mailcount='0')
            insert.save()
            return HttpResponseRedirect('/')

    hostnames=[]       
    for j in temp_hostname:
        hostnames.append(j.hostname)       
    dics=[]
    i=0
    for x in hostnames:
        i=i+1
        dic1=Dataobject()
        host = x
        try:
            try:
                ssl_connection_setting = Context(SSLv3_METHOD)
            except ValueError:
                ssl_connection_setting = Context(TLSv1_2_METHOD)
            ssl_connection_setting.set_timeout(5)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, 443))
                c = Connection(ssl_connection_setting, s)
                c.set_tlsext_host_name(str.encode(host))
                c.set_connect_state()
                c.do_handshake()
                cert = c.get_peer_certificate()
                cert_protocol=c.get_protocol_version_name()
                tempissuer=str(cert.get_issuer()).split("=")
                issuerCA=tempissuer[2].split("/")
                subject_list = cert.get_subject().get_components()
                cert_byte_arr_decoded = {}
                for item in subject_list:
                    cert_byte_arr_decoded.update({item[0].decode('utf-8'): item[1].decode('utf-8')})
                if len(cert_byte_arr_decoded) > 0:
                    pass#print("Subject: ", cert_byte_arr_decoded)
                if cert_byte_arr_decoded["CN"]:
                    pass#print("Common Name: ", cert_byte_arr_decoded["CN"])
                end_date = datetime.strptime(str(cert.get_notAfter().decode('utf-8')), "%Y%m%d%H%M%SZ")
                diff = str(end_date - datetime.now()) 
                rmdays=diff.split(", ")[0]
                c.shutdown()
                s.close()
                #Dic entry for host
                dic1.hostname=host
                dic1.issueDate=datetime.strptime(str(cert.get_notBefore().decode('utf-8')), "%Y%m%d%H%M%SZ")
                dic1.enddate=datetime.strptime(str(cert.get_notAfter().decode('utf-8')), "%Y%m%d%H%M%SZ")
                dic1.id=i
                dic1.checkdiff=int(rmdays.split(" ")[0])
                dic1.issuer=issuerCA[0]
                dic1.protocol=cert_protocol
                dic1.isexpired=cert.has_expired()
                dic1.remainDays=rmdays

###############appending hostname dics together to pass as context###########
                dics.append(dic1)       
        except:
            pass      
#template rendering
    return render(request,'sslmaster/addandshow.html',{'dics':dics})




def add_show_whois(request):
    hostnames=[]
    temp_hostname=Hostnameentrywhois.objects.all()
    for j in temp_hostname:
        hostnames.append(j.hostname)

    if 'delete' in request.POST:
        delhost=(request.POST.get('addhost',False)).strip()
        if delhost in hostnames:
            del_data=Hostnameentrywhois.objects.get(hostname=delhost)
            del_data.delete()
        else:
            pass##########console handle domain not found
        return HttpResponseRedirect('/whois')
    
    elif 'add' in request.POST:
        host=(request.POST.get('addhost',False)).strip()
        if host in hostnames:
            pass
        elif len(host)==0 :
            pass
        else:
            insert=Hostnameentrywhois(hostname=host,mailcount='0')
            insert.save()
            return HttpResponseRedirect('/whois')

    hostnames=[]       
    for j in temp_hostname:
        hostnames.append(j.hostname)       
    dics=[]
    i=0
    for x in hostnames:
        i=i+1
        dic1=Dataobjectwhois()
        host = x
        query = whois.whois(host)
        ###### dic entry #######
        dic1.hostname=host
        dic1.country=query.country
        dic1.id=i
        dic1.registrar=query.registrar
        dic1.registrarurl=query.registrar_url
        dic1.organisation=query.organization
        dic1.status=query.status
        dic1.state=query.state
        dic1.iana=query.registrar_iana
        dic1.enddate=query.expiration_date
        dic1.issueDate=query.creation_date
        if query.emails !=None:
            dic1.email=query.emails
        else:
            dic1.email=["Contact Registrar"]

        #####appending dic in context disk to pass######
        dics.append(dic1)

    return render(request,'sslmaster/addandshowwhois.html',{'dics':dics})



def add_show_dns(request):
    hostnames=[]
    temp_hostname=Hostnameentrydns.objects.all()
    for j in temp_hostname:
        hostnames.append(j.hostname)

    if 'delete' in request.POST:
        delhost=(request.POST.get('addhost',False)).strip()
        if delhost in hostnames:
            del_data=Hostnameentrydns.objects.get(hostname=delhost)
            del_data.delete()
        else:
            pass##########console handle     
        return HttpResponseRedirect('/dns')
    
    elif 'add' in request.POST:
        host=(request.POST.get('addhost',False)).strip()
        if host in hostnames:
            pass######handler####
        elif len(host)==0 :
            pass########handler#####
        else:
            insert=Hostnameentrydns(hostname=host,mailcount='0')
            insert.save()
            return HttpResponseRedirect('/dns')

    hostnames=[]       
    for j in temp_hostname:
        hostnames.append(j.hostname)       
    dics=[]
    i=0
    for x in hostnames:
        i=i+1
        dic1=Dataobjectdns()
        try:
            result = dns.resolver.query(x,'A')
            ip=[]
            for ipval in result:
                ip.append(ipval)
            dic1.resolve=ip
        except:
            dic1.resolve='-'        
        try:    
            result2=  dns.resolver.query(x,'MX')
            dic1.mx=result2
        except:
            dic1.mx="-"      
        dic1.hostname=x       
        dic1.id=i 

        dics.append(dic1)

#template rendering
    return render(request,'sslmaster/addandshowdns.html',{'dics':dics})



