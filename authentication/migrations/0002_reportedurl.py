# Generated by Django 4.2.7 on 2024-04-03 15:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReportedURL',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField()),
                ('reported_at', models.DateTimeField(auto_now_add=True)),
                ('username', models.CharField(max_length=100)),
                ('unique_id', models.CharField(max_length=50, unique=True)),
            ],
        ),
    ]
