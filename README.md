<h1>Gmail Backup Tool</h1>

<p><strong>Gmail Backup Tool</strong> is a powerful and user-friendly desktop application designed to backup Gmail emails. Using the Gmail API and Google OAuth 2.0, this application allows users to download emails from their Gmail account and save them in various formats, including <code>.txt</code>, <code>.eml</code>, <code>.csv</code>, and <code>.pdf</code>. The tool is built using Python, PyQt5 for the GUI, and integrates with Gmail via Google's API.</p>

<h2>Features</h2>
<ul>
  <li><strong>OAuth 2.0 Authentication:</strong> Securely authenticate with your Gmail account using Google OAuth 2.0.</li>
  <li><strong>Multiple Email Formats:</strong> Save emails in <code>.txt</code>, <code>.eml</code>, <code>.csv</code>, or <code>.pdf</code> formats.</li>
  <li><strong>Batch Processing:</strong> Fetch and process emails in batches, with progress tracking for large volumes of emails.</li>
  <li><strong>Folder Organization:</strong> Automatically organize saved emails into folders based on their Gmail labels.</li>
  <li><strong>Live Progress and Feedback:</strong> Provides real-time progress tracking and live previews of the emails being backed up.</li>
  <li><strong>Retry Mechanism:</strong> Automatically retry failed requests with exponential backoff to handle temporary errors.</li>
</ul>

<h2>How It Works</h2>
<ol>
  <li>Authenticate using your Gmail account via Google OAuth 2.0.</li>
  <li>Select the labels you want to backup.</li>
  <li>Choose the format for saving your emails: <code>.txt</code>, <code>.eml</code>, <code>.csv</code>, or <code>.pdf</code>.</li>
  <li>Click "Start Backup" and let the application fetch and save your emails to your selected folder.</li>
</ol>

<h2>Installation</h2>
<pre><code>
# Clone the repository
git clone https://github.com/your-repo/gmail-backup-tool.git

# Navigate to the project directory
cd gmail-backup-tool

# Install required dependencies
pip install -r requirements.txt
</code></pre>

<h2>Dependencies</h2>
<ul>
  <li>Python 3.x</li>
  <li>PyQt5</li>
  <li>Google API Python Client</li>
  <li>FPDF</li>
  <li>Pandas</li>
</ul>

<h2>Usage</h2>
<pre><code>
python main.py
</code></pre>

<p>Once the application launches, follow the steps to authenticate and start backing up your Gmail emails.</p>

<h2>License</h2>
<p>This project is licensed under the MIT License.</p>
