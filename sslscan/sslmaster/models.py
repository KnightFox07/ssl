from datetime import date
import string
from django.db import models

# Create your models here.

class Dataobject:
    id:int
    hostname:string
    issueDate:string
    enddate:string
    remainDays:int
    issuer:string
    checkdiff=int
    protocol:string
    isexpired:string

class Dataobjectwhois:
    id:int
    hostname:string
    issueDate:string
    enddate:date
    registrar:string
    registrarurl:string
    organisation:string
    email:list
    country:string
    status:list
    state:string
    iana:string

class Dataobjectdns:
    id:int
    hostname:string
    mx:list
    resolve:list

class Hostnameentry(models.Model):
    hostname= models.CharField(max_length=50,default='')
    mailcount=models.CharField(max_length=1,default='0')
    def __str__(self):
         return self.hostname

class Hostnameentrywhois(models.Model):
    hostname= models.CharField(max_length=50,default='')
    mailcount=models.CharField(max_length=1,default='0')
    def __str__(self):
         return self.hostname

class Hostnameentrydns(models.Model):
    hostname= models.CharField(max_length=50,default='')
    mailcount=models.CharField(max_length=1,default='0')
    def __str__(self):
         return self.hostname