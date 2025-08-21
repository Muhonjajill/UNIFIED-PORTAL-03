# forms.py
from django import forms

from core.priority_rules import determine_priority
from .models import File, ProblemCategory, Ticket,TicketComment, Customer, Region
from django.contrib.auth.models import User
from .models import Profile, Terminal, VersionControl, ISSUE_MAPPING, CATEGORY_CHOICES
from django.forms import inlineformset_factory

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6)
    
class CustomUserCreationForm(forms.ModelForm):
    password = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email']

    def clean_password2(self):
        password = self.cleaned_data.get('password')
        password2 = self.cleaned_data.get('password2')

        if password and password2 and password != password2:
            raise forms.ValidationError("Passwords don’t match.")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
        return user
    
class FileUploadForm(forms.ModelForm):
    class Meta:
        model = File
        fields = ['title', 'description', 'category', 'access_level', 'file']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter file title'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter a brief description',
                'rows': 3
            }),
            'category': forms.Select(attrs={
                'class': 'form-control'
            }),
            'access_level': forms.Select(attrs={
                'class': 'form-control'
            }),
            'file': forms.ClearableFileInput(attrs={
                'class': 'form-control-file'
            }),
        }

class UserUpdateForm(forms.ModelForm):
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ['username', 'email']

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['avatar']

"""
class TicketForm(forms.ModelForm):
    problem_category = forms.ModelChoiceField(
        queryset=ProblemCategory.objects.all(),
        empty_label="Select Category",
        required=False,
        widget=forms.Select(attrs={"class": "form-control"})
    )
    title = forms.ChoiceField(
        choices=[("", "Select Issue")],
        required=False,
        widget=forms.Select(attrs={"class": "form-control"})
    )
    custom_created_at = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'})
    )

    class Meta:
        model = Ticket
        fields = [
            "brts_unit", "problem_category", "title", "terminal",
            "customer", "region", "description", "priority", "status"
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Automatically populate customer and region if a terminal is specified
        if 'instance' in kwargs and kwargs['instance'] and kwargs['instance'].terminal:
            terminal = kwargs['instance'].terminal
            self.fields['customer'].initial = terminal.customer
            self.fields['region'].initial = terminal.region
        elif 'terminal_id' in kwargs:  # Handle when creating new tickets and terminal_id is passed
            terminal_id = kwargs.get('terminal_id')
            if terminal_id:
                try:
                    terminal = Terminal.objects.get(id=terminal_id)
                    self.fields['customer'].initial = terminal.customer
                    self.fields['region'].initial = terminal.region
                except Terminal.DoesNotExist:
                    pass  # Handle the case where the terminal is not found

        # Populate "Issue" choices based on selected category (by PK)
        selected_cat_pk = (
            self.data.get("problem_category")
            or self.initial.get("problem_category")
        )
        if selected_cat_pk:
            try:
                cat = ProblemCategory.objects.get(pk=selected_cat_pk)
                issues = ISSUE_MAPPING.get(cat.name, [])
                self.fields["title"].choices += [
                    (i, i) for i in issues
                ]
                self.fields["title"].widget.attrs.pop("disabled", None)
            except ProblemCategory.DoesNotExist:
                pass
        else:
            self.fields["title"].widget.attrs["disabled"] = True
            #new changes to priorities
    def save(self, commit=True):
        # Automatically set the priority based on problem category, title, and description
        if not self.instance.priority:  # Only set priority if not manually defined
            category = self.cleaned_data.get('problem_category')
            title = self.cleaned_data.get('title')
            description = self.cleaned_data.get('description')
            self.instance.priority = determine_priority(category.name if category else "", title, description)

        return super().save(commit)       
"""
class TicketForm(forms.ModelForm):
    problem_category = forms.ModelChoiceField(
        queryset=ProblemCategory.objects.all(),
        empty_label="Select Category",
        required=False,
        widget=forms.Select(attrs={"class": "form-control"})
    )
    title = forms.ChoiceField(
        choices=[("", "Select Issue")],
        required=False,
        widget=forms.Select(attrs={"class": "form-control"})
    )
    custom_created_at = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'type': 'datetime-local',
            'class': 'form-control'
        })
    )
    class Meta:
        model = Ticket
        fields = [
            "brts_unit",
            "problem_category",
            "title",
            "terminal",
            "customer",
            "region",
            "description",
            "status",
        ]  # removed "priority" so form never pre-populates it
    def __init__(self, *args, **kwargs):
        # Pull out terminal_id for new-ticket initialization
        terminal_id = kwargs.pop("terminal_id", None)
        super().__init__(*args, **kwargs)
        # Pre-fill customer & region from instance or terminal_id
        terminal = getattr(self.instance, "terminal", None)
        if terminal:
            self.fields["customer"].initial = terminal.customer
            self.fields["region"].initial = terminal.region
        elif terminal_id:
            try:
                term = Terminal.objects.get(pk=terminal_id)
                self.fields["customer"].initial = term.customer
                self.fields["region"].initial = term.region
            except Terminal.DoesNotExist:
                pass
        # Populate issue choices based on selected category
        selected = self.data.get("problem_category") or self.initial.get("problem_category")
        if selected:
            try:
                cat = ProblemCategory.objects.get(pk=selected)
                issues = ISSUE_MAPPING.get(cat.name, [])
                self.fields["title"].choices = [("", "Select Issue")] + [(i, i) for i in issues]
                self.fields["title"].widget.attrs.pop("disabled", None)
            except ProblemCategory.DoesNotExist:
                self.fields["title"].widget.attrs["disabled"] = True
        else:
            self.fields["title"].widget.attrs["disabled"] = True
    def save(self, commit=True):
        # Always compute priority here (never included on the form)
        ticket = super().save(commit=False)
        cat = self.cleaned_data.get("problem_category")
        issue = self.cleaned_data.get("title") or ""
        desc = self.cleaned_data.get("description") or ""
        ticket.priority = determine_priority(
            cat.name if cat else "",
            issue,
            desc
        )
        if commit:
            ticket.save()
        return ticket
            
class ProblemCategoryForm(forms.ModelForm):
    class Meta:
        model = ProblemCategory
        fields = ['brts_unit', 'name']
        widgets = {
            'brts_unit': forms.Select(attrs={'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter category name'}),
        }

class TerminalForm(forms.ModelForm):
    class Meta:
        model = Terminal
        fields = ['customer', 'branch_name', 'cdm_name', 'serial_number', 'region', 'model', 'zone']
        widgets = {
            'customer': forms.Select(attrs={'class': 'form-control'}),
            'branch_name': forms.TextInput(attrs={'class': 'form-control', 'value': 'Main Branch'}),
            'cdm_name': forms.TextInput(attrs={'class': 'form-control'}),
            'serial_number': forms.TextInput(attrs={'class': 'form-control'}),
            'region': forms.Select(attrs={'class': 'form-control'}),
            'model': forms.TextInput(attrs={'class': 'form-control'}),
            'zone': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.branch_name:
            self.fields['branch_name'].required = False  

    
class TerminalUploadForm(forms.Form):
    file = forms.FileField(
        label='Upload CSV or Excel File',
        widget=forms.FileInput(attrs={'accept': '.csv, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'})
    )

class VersionControlForm(forms.ModelForm):
    class Meta:
        model = VersionControl
        fields = [
            'terminal', 'manufacturer', 'template', 'firmware',
            'xfs', 'ejournal',
            'brits', 'app_version', 'neo_atm'
        ]
        widgets = {
            'terminal': forms.Select(attrs={'class': 'form-control'}),
            'manufacturer': forms.Select(attrs={'class': 'form-select'}),
            'template': forms.TextInput(attrs={'class': 'form-control'}),
            'firmware': forms.TextInput(attrs={'class': 'form-control'}),
            'xfs': forms.TextInput(attrs={'class': 'form-control'}),
            'ejournal': forms.TextInput(attrs={'class': 'form-control'}),
            #'responsible': forms.TextInput(attrs={'class': 'form-control'}),
            'brits': forms.TextInput(attrs={'class': 'form-control'}),
            'app_version': forms.TextInput(attrs={'class': 'form-control'}),
            'neo_atm': forms.TextInput(attrs={'class': 'form-control'}),
        }

        
class TicketCommentForm(forms.ModelForm):
    class Meta:
        model = TicketComment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Add a comment...', 'class': 'form-control'})
        }

class TicketEditForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['status', 'priority', 'comment_summary', 'problem_category', 'description','resolution']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-control'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
            'comment_summary': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'problem_category': forms.Select(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'resolution': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }

class EscalationNoteForm(forms.Form):
    note = forms.CharField(
        label="Escalation Note",
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Add a note for the escalation'
        }),
        required=False
    )