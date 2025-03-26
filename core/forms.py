from django import forms
from django.contrib.auth.forms import UserChangeForm
from .models import User, Product

class UserRegisterForm(forms.ModelForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'placeholder': 'Email'}))
    role = forms.ChoiceField(choices=User.ROLE_CHOICES, initial='buyer', widget=forms.Select(attrs={'placeholder': 'Role'}))

    class Meta:
        model = User
        fields = ['username', 'email', 'role', 'password']
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Username'}),
            'password': forms.PasswordInput(attrs={'placeholder': 'Password'}),
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.role = self.cleaned_data['role']
        if commit:
            user.set_password(self.cleaned_data['password'])
            user.save()
        return user

class UserLoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))

class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'description', 'price', 'stock', 'category', 'image']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'Enter product name', 'class': 'w-full p-3 border rounded-lg focus:border-blue-500 focus:outline-none'}),
            'description': forms.Textarea(attrs={'placeholder': 'Describe your product', 'rows': 4, 'class': 'w-full p-3 border rounded-lg focus:border-blue-500 focus:outline-none'}),
            'price': forms.NumberInput(attrs={'placeholder': 'Enter price in ₹ (e.g., 299.99)', 'step': '0.01', 'min': '0', 'class': 'w-full p-3 border rounded-lg focus:border-blue-500 focus:outline-none'}),
            'stock': forms.NumberInput(attrs={'placeholder': 'Enter stock quantity', 'min': '0', 'class': 'w-full p-3 border rounded-lg focus:border-blue-500 focus:outline-none'}),
            'category': forms.Select(attrs={'class': 'w-full p-3 border rounded-lg focus:border-blue-500 focus:outline-none'}),
            'image': forms.FileInput(attrs={'class': 'w-full p-3 border rounded-lg', 'accept': 'image/*'}),
        }

class BuyerProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'full_name', 'phone_number', 'alternate_email', 'address', 'profile_picture']
        widgets = {
            'address': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.exclude(pk=self.instance.pk).filter(username=username).exists():
            raise forms.ValidationError('This username is already taken.')
        return username

    def clean_email(self):
        email = self.cleaned_data['email']
        if not email:
            raise forms.ValidationError('Email is required.')
        if User.objects.exclude(pk=self.instance.pk).filter(email=email).exists():
            raise forms.ValidationError('This email is already in use.')
        return email

    def clean_phone_number(self):
        phone = self.cleaned_data['phone_number']
        if phone and not phone.replace('+', '').isdigit():
            raise forms.ValidationError('Phone number must contain only digits and an optional + prefix.')
        if phone and len(phone) < 10:
            raise forms.ValidationError('Phone number must be at least 10 digits long.')
        return phone

    def clean(self):
        cleaned_data = super().clean()
        full_name = cleaned_data.get('full_name')
        if not full_name:
            raise forms.ValidationError('Full name is required.')
        return cleaned_data
    
