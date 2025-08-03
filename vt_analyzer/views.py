import os
import re
import base64
import time
import hashlib
import requests
from django.shortcuts import render
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from .forms import AnalysisForm
import logging

logger = logging.getLogger(__name__)
def get_api_key():
    """Get API key from Django settings or fallback to hardcoded"""
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
    if not api_key:
        api_key = "YOUR-KEY"
        logger.warning("Using hardcoded API key. Consider moving to Django settings.")
    return api_key
def get_headers():
    """Get headers with API key"""
    return {"x-apikey": get_api_key()}

def detect_input_type(value):
    """Detect the type of input (URL, IP, hash)"""
    if not value:
        return "unknown"
    
    value = value.strip()
    
    # URL 
    if re.match(r'^https?://', value):
        return "url"
    
    # IPv4 pattern
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ipv4_pattern, value):
        return "ip"
    
    # Hash patterns (MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars)
    if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
        return "hash"
    elif re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
        return "hash"
    elif re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
        return "hash"
    
    return "unknown"

def make_api_request(method, url, **kwargs):
    """Make API request with error handling"""
    try:
        response = requests.request(method, url, timeout=30, **kwargs)
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {e}")
        return None

def get_report(endpoint, id_):
    """Get report from VirusTotal API"""
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{id_}"
    response = make_api_request("GET", url, headers=get_headers())
    
    if response is None:
        return {"error": "Network error occurred"}
    
    if response.status_code == 404:
        return {"error": "Resource not found"}
    elif response.status_code == 429:
        return {"error": "Rate limit exceeded. Please try again later."}
    elif not response.ok:
        return {"error": f"API error: {response.status_code}"}
    
    return response.json()

def scan_url(url):
    """Scan URL with VirusTotal"""
    try:
        # Submit URL for scanning
        response = make_api_request(
            "POST",
            "https://www.virustotal.com/api/v3/urls",
            headers=get_headers(),
            data={"url": url}
        )
        
        if response is None:
            return {"error": "Network error occurred"}
        
        if not response.ok:
            error_msg = f"Failed to submit URL for scanning: {response.status_code}"
            logger.error(f"{error_msg} - {response.text}")
            return {"error": error_msg}
        
        # Get the analysis ID
        scan_data = response.json()
        analysis_id = scan_data["data"]["id"]
        
        # Wait for analysis to complete (with timeout)
        max_attempts = 40  # 5 minutes maximum
        for attempt in range(max_attempts):
            analysis_response = get_report("analyses", analysis_id)
            
            if "error" in analysis_response:
                return analysis_response
            
            status = analysis_response.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                # Get the URL report
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                return get_report("urls", url_id)
            elif status == "queued":
                time.sleep(10)  # Wait 10 seconds before checking again
            else:
                break
        
        return {"error": "Analysis timeout - please try again later"}
        
    except Exception as e:
        logger.error(f"Error in scan_url: {e}")
        return {"error": "An error occurred while scanning the URL"}

def scan_ip(ip):
    """Scan IP address with VirusTotal"""
    try:
        return make_api_request(
            "GET",
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=get_headers()
        ).json()
    except Exception as e:
        logger.error(f"Error in scan_ip: {e}")
        return {"error": "An error occurred while scanning the IP address"}

def scan_hash(hash_value):
    """Scan file hash with VirusTotal"""
    try:
        response = make_api_request(
            "GET",
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers=get_headers()
        )
        
        if response is None:
            return {"error": "Network error occurred"}
        
        return response.json()
    except Exception as e:
        logger.error(f"Error in scan_hash: {e}")
        return {"error": "An error occurred while scanning the hash"}

def scan_file(file):
    """Scan uploaded file with VirusTotal"""
    try:
        # Validate file size (VirusTotal has limits)
        max_size = 32 * 1024 * 1024  # 32MB limit for free API
        if file.size > max_size:
            return {"error": "File too large. Maximum size is 32MB."}
        
        file.seek(0)
        file_content = file.read()
        
        file_hash = hashlib.sha256(file_content).hexdigest()
    
        existing_report = scan_hash(file_hash)
        if existing_report and "data" in existing_report:
            return existing_report
        
        file.seek(0)  
        files = {'file': (file.name, file.read())}
        
        response = make_api_request(
            "POST",
            "https://www.virustotal.com/api/v3/files",
            headers=get_headers(),
            files=files
        )
        
        if response is None:
            return {"error": "Network error occurred"}
        
        if response.status_code == 409:
            return scan_hash(file_hash)
        elif not response.ok:
            error_msg = f"Failed to upload file: {response.status_code}"
            logger.error(f"{error_msg} - {response.text}")
            return {"error": error_msg}
        
        scan_data = response.json()
        analysis_id = scan_data["data"]["id"]
        
        max_attempts = 30  
        for attempt in range(max_attempts):
            analysis_response = get_report("analyses", analysis_id)
            
            if "error" in analysis_response:
                return analysis_response
            
            status = analysis_response.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return scan_hash(file_hash)
            elif status == "queued":
                time.sleep(10)
            else:
                break
        
        return {"error": "File analysis timeout - please try again later"}
        
    except Exception as e:
        logger.error(f"Error in scan_file: {e}")
        return {"error": "An error occurred while scanning the file"}

def validate_input(value, input_type):
    """Validate input based on detected type"""
    if input_type == "url":
        if len(value) > 2048:  
            raise ValidationError("URL too long")
        if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', value):
            raise ValidationError("Invalid URL format")
    
    elif input_type == "ip":
        pass
    
    elif input_type == "hash":
        pass
    
    return True

def analyze_view(request):
    """Main view for analyzing inputs with VirusTotal"""
    result = None
    error_message = None
    
    if request.method == 'POST':
        form = AnalysisForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                value = form.cleaned_data.get('input_value', '').strip()
                uploaded_file = form.cleaned_data.get('file')
                
                if uploaded_file:
                    result = scan_file(uploaded_file)
                    
                elif value:
                    input_type = detect_input_type(value)
                    
                    if input_type == "unknown":
                        error_message = "Invalid input format. Please provide a valid URL, IP address, or file hash."
                    else:
                        try:
                            validate_input(value, input_type)
                        except ValidationError as e:
                            error_message = str(e)
                        else:
                            if input_type == "url":
                                result = scan_url(value)
                            elif input_type == "ip":
                                result = scan_ip(value)
                            elif input_type == "hash":
                                result = scan_hash(value)
                else:
                    error_message = "Please provide either a text input or upload a file."
                
                if result and "error" in result:
                    error_message = result["error"]
                    result = None
                
            except Exception as e:
                logger.error(f"Unexpected error in analyze_view: {e}")
                error_message = "An unexpected error occurred. Please try again."
        
        else:
            error_message = "Form validation failed. Please check your input."
    
    else:
        form = AnalysisForm()
    
    if error_message:
        messages.error(request, error_message)
    
    return render(request, 'analyze.html', {
        'form': form, 
        'result': result,
        'error_message': error_message
    })

def format_scan_results(result):
    """Format scan results for display in template"""
    if not result or "data" not in result:
        return None
    
    data = result["data"]["attributes"]
    stats = data.get("stats", {})
    
    return {
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'undetected': stats.get('undetected', 0),
        'harmless': stats.get('harmless', 0),
        'total_scans': sum(stats.values()) if stats else 0,
        'scan_date': data.get('date'),
        'engines': data.get('scans', {})
    }

def get_threat_level(result):
    """Determine threat level based on scan results"""
    if not result or "data" not in result:
        return "unknown"
    
    stats = result["data"]["attributes"].get("stats", {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    
    if malicious > 0:
        return "high"
    elif suspicious > 2:
        return "medium"
    elif suspicious > 0:
        return "low"
    else:
        return "clean"