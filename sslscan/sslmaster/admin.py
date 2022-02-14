from django.contrib import admin
from .models import Hostnameentry, Hostnameentrydns,Hostnameentrywhois


# Register your models here.
#admin.site.register(Hostnameentry)
@admin.register(Hostnameentry)
class Model_Admin(admin.ModelAdmin):
    list_view=('id','hostname','mailcount')

@admin.register(Hostnameentrywhois)
class Model_Admin(admin.ModelAdmin):
    list_view=('id','hostname','mailcount')

@admin.register(Hostnameentrydns)
class Model_Admin(admin.ModelAdmin):
    list_view=('id','hostname')