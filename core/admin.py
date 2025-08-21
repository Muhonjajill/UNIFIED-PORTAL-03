# core/admin.py
from django.contrib import admin
from .models import FileCategory, File, FileAccessLog, Ticket, Profile, Terminal
from .models import Customer
from django.contrib.auth.models import Group
from django.db import transaction


@admin.register(FileCategory)
class FileCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'file_count')
    def file_count(self, obj):
        return obj.file_set.filter(is_deleted=False).count()
    file_count.short_description = 'Number of Files'

@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'uploaded_by', 'upload_date', 'access_level', 'is_deleted')
    list_filter = ('category', 'access_level', 'is_deleted')
    search_fields = ('title',)

@admin.register(FileAccessLog)
class FileAccessLogAdmin(admin.ModelAdmin):
    list_display = ('file', 'accessed_by', 'access_time')
    list_filter = ('access_time',)

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('title', 'created_by', 'assigned_to', 'status', 'priority', 'created_at')
    list_filter = ('status', 'priority')
    search_fields = ('title', 'description')

class CustomerAdmin(admin.ModelAdmin):
    list_display = ('name', 'overseer', 'custodian')
    search_fields = ('name',)

    def save_model(self, request, obj, form, change):
        print(f"Saving Customer: {obj.name}")  

        # Assign Overseer to group
        if obj.overseer:
            print(f"Assigning {obj.overseer.username} to the 'Customer' group") 
            obj.overseer.groups.add(Group.objects.get(name='Customer'))

        # Assign Custodian to group + ensure profile is created/updated
        if obj.custodian:
            print(f"Assigning {obj.custodian.username} to the 'Customer' group")  
            obj.custodian.groups.add(Group.objects.get(name='Customer'))

            # Create or update Profile for custodian
            profile, created = Profile.objects.get_or_create(user=obj.custodian)
            profile.customer = obj

            # Try to assign terminal for this customer (if any)
            terminal = Terminal.objects.filter(customer=obj).first()
            if terminal:
                profile.terminal = terminal
                print(f"Assigned terminal {terminal} to {obj.custodian.username}")
            else:
                print(f"No terminal found for {obj.name}, cannot assign to {obj.custodian.username}")

            profile.save()

        super().save_model(request, obj, form, change)
