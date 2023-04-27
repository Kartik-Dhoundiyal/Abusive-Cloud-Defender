from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/aws')
def aws():
    return render_template('aws.html')

@app.route('/gcp')
def gcp():
    return render_template('gcp.html')

@app.route('/azure')
def azure():
    return render_template('azure.html')

if __name__ == '__main__':
    app.run(debug=True)

