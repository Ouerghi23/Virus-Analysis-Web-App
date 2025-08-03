# 🛡️ Virus Analysis Web App

A simple Django-based web application that analyzes **URLs**, **IP addresses**, and **files (up to 32MB)** using the [VirusTotal API](https://www.virustotal.com/).  
It provides security scores, reputation information, and detailed results from 70+ antivirus engines (e.g., Bkav, Lionic, etc.).

## 🚀 Features

- ✅ Submit a **URL** or **IP address** for scanning  
- ✅ Upload a **file** (max 32MB - free API limit)  
- ✅ View:  
  - Scan date  
  - Detection count  
  - Reputation score  
  - Community votes  
  - Engine-by-engine detection results (76 engines)

## 🖥️ Technologies Used

- **Django** (Python web framework)  
- **Python Requests** (for API integration)  
- **HTML/CSS** (Django templates)  
- **VirusTotal Public API**

## 🛠️ Installation

1. **Clone the repo**
   ```bash
   git clone https://github.com/Ouerghi23/Virus-Analysis-Web-App.git
   cd Virus-Analysis-Web-App
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Add your VirusTotal API key**
   
   In `settings.py` or in a `.env` file (recommended), add:
   ```python
   API_KEY = "your_virustotal_api_key"
   ```

5. **Run the server**
   ```bash
   python manage.py runserver
   ```

## 📝 Usage

1. Open your browser and navigate to `http://localhost:8000`
2. Choose your analysis type:
   - Enter a URL or IP address
   - Upload a file (max 32MB)
3. Click "Analyze" and view the results

## 🔑 Getting a VirusTotal API Key

1. Go to [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Navigate to your profile settings
4. Copy your API key

## 📊 API Limits

- **Free tier**: 4 requests per minute
- **File size limit**: 32MB
- **Supported file types**: All file types supported by VirusTotal
🤝 Contact
Developed by Chaima Ouerghi

Email: shaymaouerghi0@gmail.com

LinkedIn: [[[linkedin-profile](https://www.linkedin.com/in/ouerghi-cha%C3%AFma-ab24b9252/)]


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Always ensure you have permission before analyzing files or URLs that don't belong to you.
