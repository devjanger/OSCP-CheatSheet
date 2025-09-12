from flask import Flask, request, redirect, send_from_directory, render_template_string
import os

UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

HTML = '''
<!doctype html>
<title>File Upload & Download</title>
<h1>📤 Upload File</h1>
<form method=post enctype=multipart/form-data>
  <input type=file name=file><input type=submit value=Upload>
</form>
<hr>
<h2>📁 Uploaded Files</h2>
<ul>
  {% for file in files %}
    <li><a href="/download/{{ file }}">{{ file }}</a></li>
  {% endfor %}
</ul>
'''

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        if f:
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
            return redirect('/')
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template_string(HTML, files=files)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001)
