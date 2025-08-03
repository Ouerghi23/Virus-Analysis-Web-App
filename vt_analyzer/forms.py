# forms.py
from django import forms

class AnalysisForm(forms.Form):
    input_value = forms.CharField(
        max_length=2048,
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': 'URL, adresse IP ou hash de fichier...',
            'class': 'form-control'
        }),
        help_text="Entrez une URL (http://...), une adresse IP (192.168.1.1) ou un hash de fichier (MD5, SHA1, SHA256)"
    )
    
    file = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '*/*'
        }),
        help_text="Ou sélectionnez un fichier à analyser (max 32MB)"
    )
    
    def clean(self):
        cleaned_data = super().clean()
        input_value = cleaned_data.get('input_value')
        file = cleaned_data.get('file')
        
        if not input_value and not file:
            raise forms.ValidationError("Veuillez fournir soit une valeur d'entrée soit un fichier.")
        
        return cleaned_data