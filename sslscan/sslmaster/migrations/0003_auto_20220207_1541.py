# Generated by Django 3.2.5 on 2022-02-07 10:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sslmaster', '0002_auto_20220204_1958'),
    ]

    operations = [
        migrations.CreateModel(
            name='Hostnameentrywhois',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hostname', models.CharField(default='', max_length=50)),
                ('mailcount', models.CharField(default='0', max_length=1)),
            ],
        ),
        migrations.AlterField(
            model_name='hostnameentry',
            name='hostname',
            field=models.CharField(default='', max_length=50),
        ),
    ]