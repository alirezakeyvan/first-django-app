from django import forms
from django.contrib.auth import (authenticate, get_user_model)

User = get_user_model()


class UserLoginForm(forms.Form):
    username= forms.CharField()
    password= forms.CharField(widget=forms.PasswordInput)

    def clean(self, *args, **kwargs):
        username= self.cleaned_data.get(username)
        password= self.cleaned_data.get(password)

        if username and password:
            user= authenticate(username=username,password=password)
            if not user:
                raise forms.ValidationError('user doesnt exists')
            if not user.check_password(password):
                raise forms.ValidationError('incorrect password')
            if not user.is_active:
                raise forms.ValidationError('this user is not active')
        return super(UserLoginForm,self).clean(*args, **kwargs)
class UserRegisterForm(forms,ModelForm):
    email=forms.EmailField(label='Email Address')
    email2= forms.EmailField(label='confirm mail')
    password= forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'email2',
            'password'
        ]
    class clean_email(self):
        email= self.cleaned_data.get('email')
        email2=self.clean_data.get('email2')
        if email != email2:
            raise forms.ValidationError('not same email')
        email_qs=User.objects.filter(email=email)
        if email_qs.exists():
            raise forms.ValidationError('email is already being used!')
        return email